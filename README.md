# S3 Bulk Downloader

A desktop application for downloading large sets of files from Neurophindr's S3 buckets. Users get a small credentials file from the web app, sign in with their account, and the tool handles listing and syncing the relevant buckets to a local folder — no AWS CLI knowledge required.

Built with Python, Tkinter, and [s5cmd](https://github.com/peak/s5cmd) (downloaded automatically on first run).

## Installation

### 1. Install Python

Python 3.11 or newer is required. Download it from [python.org](https://www.python.org/downloads/).

> **On Linux:** you may also need the Tkinter package separately:
> ```bash
> sudo apt install python3-tk   # Debian/Ubuntu
> sudo dnf install python3-tkinter  # Fedora
> ```

### 2. Clone or download the repository

```bash
git clone https://github.com/AinaPonseti/S3downloader.git
cd S3downloader
```

Or download and extract the ZIP from the repository page.

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Run the app

```bash
python s3_downloader.py
```

---

## Usage

### 1. Get your credentials file

From the web app, click **Download File** to get a `.json` credentials file. This file is unique to you and tied to a specific project and environment. It expires after a period of time, so if you haven't used it in a while, download a fresh one rather than reusing an old copy.

### 2. Sign in

When the app opens, you'll be asked to sign in with your Neurophindr account (username and password). This authenticates you against the system and allows the app to request and automatically renew AWS credentials on your behalf.

### 3. Open the credentials file

Click **Select downloaded file (.json)** and choose the file from step 1. The app will read it and automatically fill in:

- **Region** — the AWS region the buckets live in
- **Profile** — the AWS CLI profile name used for authentication
- **Environment** — which environment you're pulling from (e.g. staging, production)
- **Project** — the project whose data you're downloading

These fields are read-only; they come directly from your credentials file and aren't meant to be edited by hand.

### 4. Choose a destination and download

Pick a destination folder (a sensible default under your Downloads folder is pre-filled), then click **Download**. The app will:

1. List the contents of the relevant buckets — you'll see an indeterminate progress bar while this happens.
2. Check which files are already present locally and mark them as **✓ Completed** (skipping them).
3. Populate the file list with every group of files found, showing partial progress bars for groups that are only partially downloaded.
4. Begin syncing the remaining files, updating each row's status (`Downloading…`, `✓ Completed`, `✗ Error`) as it goes, along with an overall progress bar and file count.

When it finishes, you'll get a confirmation dialog. Files are organized under your destination folder by environment, project, and group, mirroring the structure of the source buckets.

**Long downloads:** if a download takes longer than the credentials allow, the app will automatically renew them in the background — you don't need to do anything.

---

## Troubleshooting

**"Credentials have expired"** — go back to the web app and download a new `.json` file.

**A row shows ✗ Error** — the corresponding files were not downloaded. Check your network connection, then try again. Previously completed files won't be re-downloaded.

**The app won't start or fails on first launch** — it may be blocked from downloading `s5cmd`. Check your network/firewall settings, or download `s5cmd` manually from the [s5cmd releases page](https://github.com/peak/s5cmd/releases) and place it at:

- Windows: `%USERPROFILE%\.s3downloader\s5cmd.exe`
- macOS/Linux: `~/.s3downloader/s5cmd`

**Login fails with "Authentication error"** — make sure you're using your Neurophindr account credentials (not your AWS credentials). If the problem persists, contact your administrator.

---

## For developers

### Requirements

- Python 3.11+
- Dependencies listed in `requirements.txt`: `boto3`, `cryptography`
- Tkinter (ships with most Python installs; on Linux install `python3-tk` separately)

### Running from source

```bash
pip install -r requirements.txt
python s3_downloader.py
```

### How it works

1. **Credentials file**: the web app produces a `.json` file containing an AWS profile block (`config_file_info`) plus metadata (region, profile name, environment, project, expiration, Cognito config). The file is wrapped in an AES-GCM encrypted envelope (`salt`, `iv`, `authTag`, `ciphertext` fields).

2. **Decryption**: the app derives a key from a shared passphrase via PBKDF2-HMAC-SHA256 (100,000 iterations) and decrypts with AES-GCM. See [Security notes](#security-notes).

3. **Authentication**: the app authenticates the user against AWS Cognito using `USER_PASSWORD_AUTH` (pool and client IDs come from the credentials file, so they can vary per institution/deployment). The Cognito tokens are kept in memory for the duration of the session.

4. **Credentials merge**: the decrypted AWS profile block is written into `~/.credentials-file`, replacing any existing block with the same profile name. This file is passed to `s5cmd` via `AWS_SHARED_CREDENTIALS_FILE`.

5. **Local file check**: before listing anything remotely, the app scans the destination folder, removes zero-byte and incomplete files left by interrupted previous runs (`.s5cmd`, `.tmp`, `.part` extensions), and counts how many valid files are already present per group. Groups that are fully present are marked done immediately without re-downloading.

6. **Listing**: `s5cmd ls` is run against the `analysis` and `output` buckets for the given environment/project to enumerate files and group them (by top-level prefix for analysis buckets, by the first two path segments for output buckets). Listing runs in parallel across buckets.

7. **Syncing**: a batch file of `sync --size-only` commands (one per group) is built and run via `s5cmd run`. The app parses `s5cmd`'s stdout line-by-line to update per-group status and overall progress in the UI. Groups already fully present locally are excluded from the batch entirely.

8. **Automatic credential renewal**: a background thread monitors the STS credential expiration. If fewer than 5 minutes remain, it refreshes the Cognito token silently (using the refresh token, no password needed) and calls the credential Lambda via its Function URL to obtain fresh STS credentials, then overwrites `~/.credentials-file`. This happens transparently without interrupting the download.

9. **s5cmd bootstrap**: if `s5cmd` isn't already present under `~/.s3downloader/`, the app downloads and extracts the appropriate release archive for the current OS/architecture from the [s5cmd GitHub releases](https://github.com/peak/s5cmd/releases). The pinned version is set by `S5CMD_VERSION` in the source.

### Building executables

To build locally:

```bash
pip install pyinstaller -r requirements.txt
pyinstaller --onefile --windowed --name s3-downloader s3_downloader.py   # Windows/Linux
pyinstaller --onedir --windowed --name s3-downloader s3_downloader.py    # macOS
```

The output will be in `dist/`. On macOS this is a `.app` bundle — zip it before attaching to a GitHub Release:

```bash
cd dist && zip -r s3-downloader-macos.zip s3-downloader.app
```

> **Note (macOS):** unsigned apps will show a security warning. Right-click → Open → Open to bypass it the first time. If macOS reports the app as "damaged", run `xattr -cr /path/to/s3-downloader.app` first.

> **Note (Windows):** SmartScreen will show "Windows protected your PC." Click **More info** → **Run anyway**.

> **Note (Linux):** `--windowed` still requires a display server (X11/Wayland) at runtime.

### Security notes

This project uses a **hardcoded decryption passphrase** (`DECRYPTION_PASSPHRASE`) shared across all builds. This is a known limitation:

- The passphrase is the same for every user and every build, and is visible to anyone with access to the source or a decompiled binary.
- The encryption layer should be treated as **obfuscation, not access control** — it deters casual inspection of the credentials file but does not prevent someone with the application from decrypting it.
- Real access control comes from Cognito authentication: credentials files are useless without a valid account login.

If a stronger boundary is needed (e.g. credentials files should only be decryptable by their intended recipient), consider per-user key derivation or asymmetric encryption.

### Known limitations

- Progress reporting relies on parsing `s5cmd`'s stdout format. If that format changes between versions, status tracking may break even though downloads still succeed. The pinned `S5CMD_VERSION` exists to avoid this — bump it deliberately.
- Bucket listing and downloading happen on a single background thread per run; very large buckets (100k+ objects) may take a while to list before any download progress is shown.
- The credential renewal watcher checks every 60 seconds, so in the worst case it may start renewing with just under 4 minutes to spare rather than the full 5.