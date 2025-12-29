import argparse
import os
from typing import Dict, Iterable, List, Optional, Tuple

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

SCOPES = ["https://www.googleapis.com/auth/drive"]
CREDENTIALS_DIR = "credentials"
TOKEN_DIR = "token"


def get_drive_service(credentials_path: str, token_path: str):
    """
    Build an authenticated Drive API client, prompting the user once for OAuth consent.
    """
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
    return build("drive", "v3", credentials=creds, cache_discovery=False)


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
    args = parser.parse_args()

    if not args.folder_name and not args.folder_id:
        raise SystemExit("You must provide --folder-name or --folder-id.")

    owner_credentials = args.credentials or os.path.join(CREDENTIALS_DIR, args.owner_email)
    owner_token = args.token or os.path.join(TOKEN_DIR, f"{args.owner_email}.json")

    if not os.path.exists(owner_credentials):
        raise SystemExit(f"Owner credentials not found at {owner_credentials}")

    service = get_drive_service(owner_credentials, owner_token)
    target_service = None
    if args.auto_accept:
        if not args.target_credentials:
            target_credentials = os.path.join(CREDENTIALS_DIR, args.target_email)
        else:
            target_credentials = args.target_credentials
        if not os.path.exists(target_credentials):
            raise SystemExit(f"Target credentials not found at {target_credentials}")
        target_token = args.target_token or os.path.join(TOKEN_DIR, f"{args.target_email}.json")
        target_service = get_drive_service(target_credentials, target_token)

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

        status = None
        try:
            status = transfer_file_ownership(service, file_obj["id"], args.target_email)
            if status == "pending_owner" and target_service:
                try:
                    accept_status = accept_pending_transfer(
                        target_service, file_obj["id"], args.target_email
                    )
                    if accept_status == "accepted":
                        status = "accepted"
                except HttpError as err:
                    failures.append(f"{path_str} ({file_obj['id']}): accept: {err}")
                    stats["errors"] += 1
                    print(f"error          {path_str}: accept: {err}")
                    continue
            stats[status] += 1
            print(f"{status:14} {path_str}")
        except HttpError as err:
            stats["errors"] += 1
            failures.append(f"{path_str} ({file_obj['id']}): {err}")
            print(f"error          {path_str}: {err}")

    print("\nSummary:")
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
        print(f"- {label}: {stats[key]}")

    if failures:
        print("\nFailures:")
        for item in failures:
            print(f"- {item}")


if __name__ == "__main__":
    main()
