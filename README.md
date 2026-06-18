# S3 Bulk Downloader

A desktop application for downloading large sets of files from Neurophindr's S3 buckets. Users get a small credentials file from the web app, open it in this tool, and the tool handles listing and syncing the relevant buckets to a local folder — no AWS CLI knowledge required.

Built with Python, Tkinter, and [s5cmd](https://github.com/peak/s5cmd) (downloaded automatically on first run).

## Installation

### 1. Install the application

Download the latest build for your operating system from the [Releases page](https://github.com/AinaPonseti/S3downloader/releases), or get it from the link provided in the web app. No other setup is required — the app will download its own copy of `s5cmd` the first time it runs.

> **Note:** these builds aren't currently code-signed, so your OS will show a security warning the first time you open the app. This doesn't mean anything is wrong — see below for how to proceed.
>
> **On macOS:** you'll see "[app name] can't be opened because it is from an unidentified developer" (or it may say the app is damaged). Right-click (or Control-click) the app and choose **Open**, then confirm **Open** in the dialog that follows. You only need to do this once — after that, double-clicking works normally. If macOS reports the app as "damaged," instead run this once in Terminal before opening it: `xattr -cr /path/to/s3-downloader.app`.
>
> **On Windows:** SmartScreen will show "Windows protected your PC." Click **More info**, then **Run anyway**. This warning appears for any unsigned executable regardless of how trustworthy it is, and will keep appearing on each new release until the app is code-signed.

### 2. Get your credentials file

From the web app, click **Download File** to get a `.json` credentials file. This file is unique to you and tied to a specific project and environment. It also expires after a period of time, so if you haven't used it in a while, download a fresh one rather than reusing an old copy.

### 3. Open the file in the app

Launch S3 Bulk Downloader and click **Select downloaded file (.json)**, then choose the file from step 2. The app will read it and automatically fill in:

- **Region** — the AWS region the buckets live in
- **Profile** — the AWS CLI profile name used for authentication
- **Environment** — which environment you're pulling from (e.g. staging, production)
- **Project** — the project whose data you're downloading

These fields are read-only; they come directly from your credentials file and aren't meant to be edited by hand.

### 4. Choose a destination and download

Pick a destination folder (a sensible default under your Downloads folder is pre-filled), then click **Download**. The app will:

1. List the contents of the relevant buckets — you'll see an indeterminate progress bar while this happens.
2. Populate the file list with every group of files it found.
3. Begin syncing files to your destination folder, updating each row's status (`Downloading…`, `✓ Completed`, `✗ Error`) as it goes, along with an overall progress bar and file count.

When it finishes, you'll get a confirmation dialog. Files are organized under your destination folder by environment, project, and group, mirroring the structure of the source buckets.

### Troubleshooting

If you see **"Credentials have expired"**, go back to the web app and download a new `.json` file — credentials files are time-limited and can't be renewed in place.

If a row shows **✗ Error**, the corresponding files were not downloaded successfully. Check your network connection and AWS permissions for the profile shown in the form, then try again; previously completed files won't be re-downloaded since `s5cmd sync` only transfers what's missing or changed.

If the **app won't start** or fails on first launch, it may be blocked from downloading `s5cmd`. Check your network/firewall settings, or download `s5cmd` manually and place it at:

- Windows: `%USERPROFILE%\.s3downloader\s5cmd.exe`
- macOS/Linux: `~/.s3downloader/s5cmd`

## For developers

### Requirements

- Python 3.11+
- Dependencies: `cryptography` (Tkinter ships with most Python installs; on Linux you may need your distro's `python3-tk` package separately)

```bash
pip install cryptography
```

### Running from source

```bash
python s3_downloader.py
```

### How it works

1. **Credentials file**: the web app produces a `.json` file containing an AWS profile block (`config_file_info`) plus metadata (region, profile name, environment, project, expiration). This may be wrapped in an AES-GCM encrypted envelope (`salt`, `iv`, `authTag`, `ciphertext` fields) or provided as plain JSON.
2. **Decryption**: if encrypted, the app derives a key from a passphrase via PBKDF2-HMAC-SHA256 (100,000 iterations) and decrypts with AES-GCM. The decryption passphrase is currently a hardcoded constant in the source (`DECRYPTION_PASSPHRASE`) — see [Security notes](#security-notes) below before relying on this for anything sensitive.
3. **Credentials merge**: the decrypted AWS profile block is written into `~/.credentials-file`, replacing any existing block with the same profile name. This file is passed to `s5cmd` via `AWS_SHARED_CREDENTIALS_FILE`.
4. **Listing**: `s5cmd ls` is run against the `analysis` and `output` buckets for the given environment/project to enumerate files and group them (by top-level prefix for analysis buckets, by the first two path segments for output buckets).
5. **Syncing**: a batch file of `sync` commands (one per group) is built and run via `s5cmd run`. The app parses `s5cmd`'s stdout line-by-line to update per-group status and overall progress in the UI.
6. **s5cmd bootstrap**: if `s5cmd` isn't already present under `~/.s3downloader/`, the app downloads and extracts the appropriate release archive for the current OS/architecture from the [s5cmd GitHub releases](https://github.com/peak/s5cmd/releases). The pinned version is set by `S5CMD_VERSION` in the source.

### Building executables

Executables for Windows, macOS, and Linux are built via GitHub Actions (`.github/workflows/main.yml`) using PyInstaller, triggered on version tags (`v*`) or manually via `workflow_dispatch`. The matrix uses `fail-fast: false` so one OS failing doesn't cancel the others. macOS builds use `--onedir` (PyInstaller's `--onefile` is incompatible with `--windowed` `.app` bundles on macOS); Windows and Linux use `--onefile`. Each platform's output is uploaded as a workflow artifact.

To build locally:

```bash
pip install pyinstaller cryptography
pyinstaller --onefile --windowed --name s3-downloader s3_downloader.py   # Windows/Linux
pyinstaller --onedir --windowed --name s3-downloader s3_downloader.py    # macOS
```

The output will be in `dist/`. On macOS this is a `.app` bundle (a folder, not a single file) — zip it before attaching to a GitHub Release, since release assets must be single files:

```bash
cd dist && zip -r s3-downloader-macos.zip s3-downloader.app
```

> **Note (Linux):** `--windowed` still requires a display server (X11/Wayland) at runtime since the app uses Tkinter. A binary built on a headless CI runner will build successfully but won't run on a headless machine.

> **Note (code signing):** none of the released builds are currently code-signed or notarized, which is why users see OS security warnings on first launch (see [Troubleshooting](#troubleshooting) above). Signing requires a paid Apple Developer account (macOS, plus notarization) and a code signing certificate, ideally EV, for reliable SmartScreen reputation (Windows). If this project moves beyond internal/small-team use, revisit this.

### Security notes

This project currently uses a **hardcoded decryption passphrase** (`DECRYPTION_PASSPHRASE` in `s3_downloader.py`) shared across all builds. This is a known limitation, not an oversight:

- The passphrase is the same for every user and every build, and it's visible to anyone with access to the source or a decompiled binary.
- This means the encryption layer should be treated as **obfuscation, not access control** — it deters casual inspection or tampering with the credentials file but does not prevent someone with the application in hand from decrypting any credentials file produced for it.
- If a real security boundary is needed here (e.g. credentials files should only be decryptable by their intended recipient), this will need a different approach — for example, per-user or per-download key derivation, or moving to asymmetric encryption so the client only ever holds a public key.

If you're extending this project and credentials sensitivity increases, revisit this before shipping.

### Known limitations

- Progress reporting relies on parsing `s5cmd`'s stdout format; if that format changes between `s5cmd` versions, status tracking may break even though downloads still succeed. The pinned `S5CMD_VERSION` exists to avoid this — bump it deliberately, not automatically.
- Bucket listing and downloading both happen on a single background thread per run; very large buckets (100k+ objects) may take a while to list before any download progress is shown.
