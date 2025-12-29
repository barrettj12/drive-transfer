import argparse
import json
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Iterable, List, Optional, Tuple

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

SCOPES = ["https://www.googleapis.com/auth/drive"]
CREDENTIALS_DIR = "credentials"
TOKEN_DIR = "token"
thread_local = threading.local()


def load_credentials(credentials_path: str, token_path: str) -> Credentials:
    """Load and refresh OAuth credentials, prompting for consent if needed."""
    creds = None
    token_dir = os.path.dirname(token_path)
    if token_dir:
        os.makedirs(token_dir, exist_ok=True)
    if os.path.exists(token_path):
        creds = Credentials.from_authorized_user_file(token_path, SCOPES)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(credentials_path, SCOPES)
            creds = flow.run_local_server(port=0)
        with open(token_path, "w", encoding="utf-8") as token_file:
            token_file.write(creds.to_json())
    return creds


def get_drive_service(credentials_path: str, token_path: str):
    """
    Build an authenticated Drive API client, prompting the user once for OAuth consent.
    """
    creds = load_credentials(credentials_path, token_path)
    return build("drive", "v3", credentials=creds, cache_discovery=False)


def format_duration(seconds: float) -> str:
    seconds = int(seconds)
    if seconds < 60:
        return f"{seconds}s"
    minutes, sec = divmod(seconds, 60)
    if minutes < 60:
        return f"{minutes}m{sec:02d}s"
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h{minutes:02d}m"


def find_folder_id(service, folder_name: str, folder_id: Optional[str]) -> str:
    if folder_id:
        return folder_id
    safe_name = folder_name.replace("'", "\\'")
    query = (
        "mimeType='application/vnd.google-apps.folder' and trashed=false "
        f"and name='{safe_name}' and 'me' in owners"
    )
    resp = (
        service.files()
        .list(
            q=query,
            spaces="drive",
            fields="files(id,name,parents)",
            pageSize=2,
            supportsAllDrives=False,
            includeItemsFromAllDrives=False,
            corpora="user",
            orderBy="modifiedTime desc",
        )
        .execute()
    )
    matches = resp.get("files", [])
    if not matches:
        raise ValueError(f"No folder named '{folder_name}' found in your My Drive.")
    if len(matches) > 1:
        print(
            f"Warning: multiple folders named '{folder_name}' found; using the first match "
            f"(id={matches[0]['id']}). Consider passing --folder-id for certainty."
        )
    return matches[0]["id"]


def list_children(service, folder_id: str) -> Iterable[Dict]:
    page_token = None
    while True:
        resp = (
            service.files()
            .list(
                q=f"'{folder_id}' in parents and trashed=false",
                spaces="drive",
                fields=(
                    "nextPageToken, files(id,name,mimeType,ownedByMe,quotaBytesUsed,"
                    "driveId,parents,size)"
                ),
                pageSize=1000,
                supportsAllDrives=False,
                includeItemsFromAllDrives=False,
                corpora="user",
                pageToken=page_token,
            )
            .execute()
        )
        for item in resp.get("files", []):
            yield item
        page_token = resp.get("nextPageToken")
        if not page_token:
            break


def walk_files(service, root_folder_id: str) -> Iterable[Tuple[Dict, List[str]]]:
    stack: List[Tuple[str, List[str]]] = [(root_folder_id, [])]
    while stack:
        current_id, current_path = stack.pop()
        for item in list_children(service, current_id):
            item_path = current_path + [item["name"]]
            if item["mimeType"] == "application/vnd.google-apps.folder":
                stack.append((item["id"], item_path))
                continue
            yield item, item_path


def should_skip(file_obj: Dict) -> Optional[str]:
    if file_obj.get("driveId"):
        return "shared_drive_item"
    if not file_obj.get("ownedByMe"):
        return "not_owned"
    quota_used = int(file_obj.get("quotaBytesUsed") or 0)
    if quota_used == 0:
        return "zero_quota"
    size_value = int(file_obj.get("size") or 0)
    if size_value == 0 and file_obj.get("size") is not None:
        return "zero_size"
    return None


def transfer_file_ownership(service, file_id: str, target_email: str) -> str:
    """
    Attempt to transfer ownership using the current owner. Returns a status string:
    - transferred: ownership change succeeded
    - pending_owner: issued a pending owner request (target must accept)
    - already_owner: target already owns the file
    """
    perms_resp = (
        service.permissions()
        .list(
            fileId=file_id,
            fields="permissions(id,emailAddress,role,type,pendingOwner)",
            supportsAllDrives=False,
        )
        .execute()
    )
    permissions = perms_resp.get("permissions", [])
    target_perm = next(
        (p for p in permissions if p.get("emailAddress") == target_email and p.get("type") == "user"),
        None,
    )
    if target_perm and target_perm.get("role") == "owner":
        return "already_owner"

    def ensure_pending_owner():
        # Request ownership; Drive will email the target to accept if required.
        if target_perm:
            service.permissions().update(
                fileId=file_id,
                permissionId=target_perm["id"],
                body={"role": "writer", "pendingOwner": True},
                transferOwnership=False,
                supportsAllDrives=False,
            ).execute()
        else:
            service.permissions().create(
                fileId=file_id,
                body={
                    "type": "user",
                    "role": "writer",
                    "emailAddress": target_email,
                    "pendingOwner": True,
                },
                transferOwnership=False,
                sendNotificationEmail=True,
                supportsAllDrives=False,
            ).execute()

    try:
        if target_perm:
            service.permissions().update(
                fileId=file_id,
                permissionId=target_perm["id"],
                body={"role": "owner"},
                transferOwnership=True,
                supportsAllDrives=False,
            ).execute()
        else:
            service.permissions().create(
                fileId=file_id,
                body={"type": "user", "role": "owner", "emailAddress": target_email},
                transferOwnership=True,
                sendNotificationEmail=False,
                supportsAllDrives=False,
            ).execute()
        return "transferred"
    except HttpError as err:
        message = err.content.decode() if hasattr(err, "content") else str(err)
        lower_msg = message.lower()
        if "pending owner" in lower_msg or "consent is required to transfer ownership" in lower_msg:
            ensure_pending_owner()
            return "pending_owner"
        raise


def accept_pending_transfer(target_service, file_id: str, target_email: str) -> str:
    """
    Accept a pending ownership request using the target user's credentials.
    Returns:
    - accepted: the target account is now owner
    - missing_permission: pending owner permission not found
    """
    perms_resp = (
        target_service.permissions()
        .list(
            fileId=file_id,
            fields="permissions(id,emailAddress,role,type,pendingOwner)",
            supportsAllDrives=False,
        )
        .execute()
    )
    target_perm = next(
        (p for p in perms_resp.get("permissions", []) if p.get("emailAddress") == target_email),
        None,
    )
    if not target_perm:
        return "missing_permission"
    target_service.permissions().update(
        fileId=file_id,
        permissionId=target_perm["id"],
        body={"role": "owner"},
        transferOwnership=True,
        supportsAllDrives=False,
    ).execute()
    return "accepted"


def main():
    parser = argparse.ArgumentParser(
        description="Recursively transfer Drive file ownership under a folder."
    )
    parser.add_argument("--owner-email", required=True, help="Current owner account email.")
    parser.add_argument("--target-email", required=True, help="Destination account to own the files.")
    parser.add_argument(
        "--folder-name",
        help="Name of the root folder in My Drive to traverse (ignored if --folder-id is set).",
    )
    parser.add_argument("--folder-id", help="Explicit folder id to traverse.")
    parser.add_argument(
        "--credentials",
        help="Override path to OAuth client credentials for the owner account.",
    )
    parser.add_argument(
        "--token",
        help="Override path to store OAuth access/refresh token for the owner account.",
    )
    parser.add_argument(
        "--target-credentials",
        help="Override path to OAuth client credentials for the target account (used to auto-accept transfers).",
    )
    parser.add_argument(
        "--target-token",
        help="Override path to store OAuth access/refresh token for the target account.",
    )
    parser.add_argument(
        "--auto-accept",
        action="store_true",
        help="If set, uses target credentials to accept pending ownership requests automatically.",
    )
    parser.add_argument("--dry-run", action="store_true", help="List actions without transferring.")
    parser.add_argument(
        "--workers",
        type=int,
        default=5,
        help="Number of parallel workers for transfers (defaults to 5).",
    )
    parser.add_argument(
        "--scan-heartbeat",
        type=int,
        default=5,
        help="Seconds between scan progress updates while enumerating files (default 5).",
    )
    parser.add_argument(
        "--expected-total",
        type=int,
        help="Optional expected total file count to show % progress and ETA during scan.",
    )
    args = parser.parse_args()

    if not args.folder_name and not args.folder_id:
        raise SystemExit("You must provide --folder-name or --folder-id.")

    owner_credentials = args.credentials or os.path.join(CREDENTIALS_DIR, args.owner_email)
    owner_token = args.token or os.path.join(TOKEN_DIR, f"{args.owner_email}.json")

    if not os.path.exists(owner_credentials):
        raise SystemExit(f"Owner credentials not found at {owner_credentials}")

    owner_creds = load_credentials(owner_credentials, owner_token)
    owner_creds_json = owner_creds.to_json()
    service = build("drive", "v3", credentials=owner_creds, cache_discovery=False)

    target_creds_json = None
    if args.auto_accept:
        if not args.target_credentials:
            target_credentials = os.path.join(CREDENTIALS_DIR, args.target_email)
        else:
            target_credentials = args.target_credentials
        if not os.path.exists(target_credentials):
            raise SystemExit(f"Target credentials not found at {target_credentials}")
        target_token = args.target_token or os.path.join(TOKEN_DIR, f"{args.target_email}.json")
        target_creds = load_credentials(target_credentials, target_token)
        target_creds_json = target_creds.to_json()

    root_id = find_folder_id(service, args.folder_name, args.folder_id)

    stats: Dict[str, int] = {
        "scanned": 0,
        "skipped_shared_drive": 0,
        "skipped_not_owned": 0,
        "skipped_zero_quota": 0,
        "skipped_zero_size": 0,
        "transferred": 0,
        "pending_owner": 0,
        "accepted": 0,
        "already_owner": 0,
        "errors": 0,
    }
    failures: List[str] = []

    work_items: List[Tuple[str, str]] = []

    scan_start = time.time()
    last_heartbeat = scan_start
    expected_total = args.expected_total if args.expected_total and args.expected_total > 0 else None
    print("Scanning for files...", flush=True)

    for file_obj, rel_path in walk_files(service, root_id):
        stats["scanned"] += 1
        skip_reason = should_skip(file_obj)
        if skip_reason:
            stats[f"skipped_{skip_reason}"] += 1
            continue

        path_str = "/".join(rel_path)
        if args.dry_run:
            print(f"[DRY RUN] Would process: {path_str} ({file_obj['id']})")
            continue

        work_items.append((file_obj["id"], path_str))

        now = time.time()
        if now - last_heartbeat >= args.scan_heartbeat:
            elapsed = now - scan_start
            rate = stats["scanned"] / elapsed if elapsed > 0 else 0.0
            msg = (
                f"Scanning... {stats['scanned']} items seen in {format_duration(elapsed)} "
                f"({rate:.2f} items/s)"
            )
            if expected_total:
                pct = min(100.0, (stats["scanned"] / expected_total) * 100.0)
                remaining = max(expected_total - stats["scanned"], 0)
                eta = format_duration(remaining / rate) if rate > 0 else "?"
                msg += f" | {pct:.1f}% (~ETA {eta} if total={expected_total})"
            print(msg, flush=True)
            last_heartbeat = now

    scan_elapsed = time.time() - scan_start
    print(
        f"Scan complete: {stats['scanned']} items seen in {format_duration(scan_elapsed)} "
        f"({(stats['scanned']/scan_elapsed) if scan_elapsed>0 else 0:.2f} items/s)",
        flush=True,
    )

    if args.dry_run or not work_items:
        print("\nSummary:", flush=True)
        for key, label in [
            ("scanned", "Files scanned"),
            ("transferred", "Ownership transferred"),
            ("accepted", "Auto-accepted pending requests"),
            ("pending_owner", "Pending owner requests"),
            ("already_owner", "Already owned by target"),
            ("skipped_shared_drive", "Skipped (shared drive items)"),
            ("skipped_not_owned", "Skipped (not owned)"),
            ("skipped_zero_quota", "Skipped (no storage quota usage)"),
            ("skipped_zero_size", "Skipped (size 0)"),
            ("errors", "Errors"),
        ]:
            print(f"- {label}: {stats[key]}", flush=True)

        if failures:
            print("\nFailures:", flush=True)
            for item in failures:
                print(f"- {item}", flush=True)
        return

    lock = threading.Lock()

    def get_thread_services():
        if not hasattr(thread_local, "owner_service"):
            owner_thread_creds = Credentials.from_authorized_user_info(
                json.loads(owner_creds_json), SCOPES
            )
            thread_local.owner_service = build(
                "drive", "v3", credentials=owner_thread_creds, cache_discovery=False
            )
        if target_creds_json:
            if not hasattr(thread_local, "target_service"):
                target_thread_creds = Credentials.from_authorized_user_info(
                    json.loads(target_creds_json), SCOPES
                )
                thread_local.target_service = build(
                    "drive", "v3", credentials=target_thread_creds, cache_discovery=False
                )
        else:
            thread_local.target_service = None
        return thread_local.owner_service, getattr(thread_local, "target_service", None)

    print(f"Starting transfers for {len(work_items)} files using {args.workers} workers", flush=True)

    def worker(file_id: str, path_str: str):
        owner_service, target_service = get_thread_services()
        try:
            status = transfer_file_ownership(owner_service, file_id, args.target_email)
            if status == "pending_owner" and target_service:
                try:
                    accept_status = accept_pending_transfer(target_service, file_id, args.target_email)
                    if accept_status == "accepted":
                        status = "accepted"
                except HttpError as err:
                    with lock:
                        stats["errors"] += 1
                        failures.append(f"{path_str} ({file_id}): accept: {err}")
                    print(f"error          {path_str}: accept: {err}", flush=True)
                    return
            with lock:
                stats[status] += 1
            print(f"{status:14} {path_str}", flush=True)
        except HttpError as err:
            message = err.content.decode() if hasattr(err, "content") else str(err)
            lower_msg = message.lower()
            if "insufficientfilepermissions" in lower_msg and target_service:
                try:
                    accept_status = accept_pending_transfer(target_service, file_id, args.target_email)
                    if accept_status == "accepted":
                        with lock:
                            stats["accepted"] += 1
                        print(f"{'accepted':14} {path_str}", flush=True)
                        return
                except HttpError as accept_err:
                    with lock:
                        stats["errors"] += 1
                        failures.append(f"{path_str} ({file_id}): accept-after-insufficient: {accept_err}")
                    print(f"error          {path_str}: accept-after-insufficient: {accept_err}", flush=True)
                    return

            with lock:
                stats["errors"] += 1
                failures.append(f"{path_str} ({file_id}): {err}")
            print(f"error          {path_str}: {err}", flush=True)

    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = [executor.submit(worker, fid, path) for fid, path in work_items]
        for _ in as_completed(futures):
            pass

    print("\nSummary:", flush=True)
    for key, label in [
        ("scanned", "Files scanned"),
        ("transferred", "Ownership transferred"),
        ("accepted", "Auto-accepted pending requests"),
        ("pending_owner", "Pending owner requests"),
        ("already_owner", "Already owned by target"),
        ("skipped_shared_drive", "Skipped (shared drive items)"),
        ("skipped_not_owned", "Skipped (not owned)"),
        ("skipped_zero_quota", "Skipped (no storage quota usage)"),
        ("skipped_zero_size", "Skipped (size 0)"),
        ("errors", "Errors"),
    ]:
        print(f"- {label}: {stats[key]}", flush=True)

    if failures:
        print("\nFailures:", flush=True)
        for item in failures:
            print(f"- {item}", flush=True)


if __name__ == "__main__":
    main()
