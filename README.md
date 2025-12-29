# Drive Ownership Transfer

Recursively transfer ownership of files inside a Google Drive folder to another account while preserving the folder structure. The script skips items that don't consume your storage (0-byte or no quota usage), items you don't own, and files in shared drives. Folders themselves are not transferred.

## Setup

1) Install dependencies (inside a virtualenv is recommended):
```bash
pip install -r requirements.txt
```

2) Place OAuth client credentials for each account under `credentials/` named by email. Example:
```
credentials/
  my.email1@gmail.com
  my.email2@gmail.com
```

3) Tokens will be created automatically on first run and saved under `token/<email>.json`.

## Usage

Basic dry run (no writes):
```bash
python transfer_drive_files.py \
  --owner-email OWNER@example.com \
  --target-email TARGET@example.com \
  --folder-name "Folder To Move" \
  --dry-run
```

Run for real with a folder id:
```bash
python transfer_drive_files.py \
  --owner-email OWNER@example.com \
  --target-email TARGET@example.com \
  --folder-id YOUR_FOLDER_ID
```

Auto-accept pending ownership (target consents immediately using its credentials):
```bash
python transfer_drive_files.py \
  --owner-email OWNER@example.com \
  --target-email TARGET@example.com \
  --folder-id YOUR_FOLDER_ID \
  --auto-accept
```

Notes:
- Use `--folder-id` for precision; `--folder-name` searches your My Drive for the first matching folder you own.
- If either credential file is elsewhere, override with `--credentials` (owner) and `--target-credentials`.
- Token paths can be overridden with `--token` and `--target-token`.
- `--dry-run` lists actions without transferring.

## How it works
- Traverses the specified folder tree (My Drive only).
- Skips: shared drive items, files not owned by the owner account, files with zero quota usage, and 0-byte uploads.
- Attempts a direct ownership transfer; if Drive requires consent, it issues a pending owner request. With `--auto-accept`, the target account accepts pending requests immediately.
- Prints per-file status and a summary of counts (transferred, accepted, pending, skipped, errors).
