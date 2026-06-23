from datetime import datetime, timezone
import os
import sys
import json
import platform
import uuid
import zipfile
import tarfile
import subprocess
import threading
import urllib.request
import base64
import hashlib
import time
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from concurrent.futures import ThreadPoolExecutor
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

try:
    import boto3
    COGNITO_AVAILABLE = True
except ImportError:
    COGNITO_AVAILABLE = False

# ---------------------------------------------------------------------------
# ── Shared application state ─────────────────────────────────────────────────
# Passed between windows so every screen reads the same values.
# ---------------------------------------------------------------------------

class AppState:
    def __init__(self):
        self.region               = ""
        self.profile              = ""
        self.environment          = ""
        self.project              = ""
        self.cognito_user_pool_id = ""
        self.cognito_client_id    = ""
        self.cognito_client_secret = ""   # empty string = no secret configured
        # Set after Cognito login — used to renew STS credentials
        self.id_token             = ""
        self.access_token         = ""
        self.refresh_token        = ""
        self.lambda_url           = ""    # URL of the credential-issuing Lambda

# ---------------------------------------------------------------------------
# ── Constants ────────────────────────────────────────────────────────────────
# ---------------------------------------------------------------------------

DECRYPTION_PASSPHRASE = "testpassphrase123"

CREDENTIALS_FILE = os.path.join(os.path.expanduser("~"), ".credentials-file")
S5CMD_VERSION    = "2.2.2"
APP_DIR          = os.path.join(os.path.expanduser("~"), ".s3downloader")
S5CMD_BIN        = os.path.join(APP_DIR, "s5cmd.exe" if platform.system() == "Windows" else "s5cmd")

UI_FLUSH_INTERVAL_MS = 150
CREATE_NO_WINDOW     = 0x08000000 if platform.system() == "Windows" else 0


# ---------------------------------------------------------------------------
# ── Encryption ───────────────────────────────────────────────────────────────
# ---------------------------------------------------------------------------

def decrypt_payload(encrypted_obj, passphrase):
    salt       = base64.b64decode(encrypted_obj["salt"])
    iv         = base64.b64decode(encrypted_obj["iv"])
    auth_tag   = base64.b64decode(encrypted_obj["authTag"])
    ciphertext = base64.b64decode(encrypted_obj["ciphertext"])
    key        = hashlib.pbkdf2_hmac("sha256", passphrase.encode(), salt, 100000, dklen=32)
    aesgcm     = AESGCM(key)
    plaintext  = aesgcm.decrypt(iv, ciphertext + auth_tag, None)
    return json.loads(plaintext.decode())


# ---------------------------------------------------------------------------
# ── Credentials file ─────────────────────────────────────────────────────────
# ---------------------------------------------------------------------------

def load_credentials_file(json_path: str, state: AppState) -> dict:
    """
    Parse the JSON credentials file, decrypt if necessary, validate fields,
    write the AWS profile entry, and populate *state* with all config values.
    """
    with open(json_path, "r", encoding="utf-8") as f:
        raw = json.load(f)

    while isinstance(raw, str):
        raw = json.loads(raw)

    if {"salt", "iv", "authTag", "ciphertext"} <= raw.keys():
        if not DECRYPTION_PASSPHRASE:
            raise ValueError("Encrypted file but no passphrase configured")
        data = decrypt_payload(raw, DECRYPTION_PASSPHRASE)
    else:
        data = raw

    required = ["environment", "region", "profile", "project",
                "config_file_info", "expiration",
                "cognito_user_pool_id", "cognito_client_id"]
    missing = [k for k in required if k not in data]
    if missing:
        raise ValueError(f"JSON file missing fields (download it again): {', '.join(missing)}")

    expiration = datetime.fromisoformat(data["expiration"])
    if expiration < datetime.now(timezone.utc):
        raise ValueError("Credentials have expired. Download the JSON file again.")

    # Write AWS profile entry
    existing = ""
    if os.path.isfile(CREDENTIALS_FILE):
        with open(CREDENTIALS_FILE, "r", encoding="utf-8") as f:
            existing = f.read()

    profile_header = f"[{data['profile']}]"
    if profile_header in existing:
        lines = existing.splitlines()
        out, skip = [], False
        for line in lines:
            if line.strip() == profile_header:
                skip = True
                continue
            if skip and line.strip().startswith("[") and line.strip() != profile_header:
                skip = False
            if not skip:
                out.append(line)
        existing = "\n".join(out).rstrip() + "\n"

    with open(CREDENTIALS_FILE, "w", encoding="utf-8") as f:
        f.write(existing.rstrip() + "\n\n" + data["config_file_info"].strip() + "\n")

    # Populate shared state so subsequent windows can use these values
    state.region               = data["region"]
    state.profile              = data["profile"]
    state.environment          = data["environment"]
    state.project              = data.get("project", "")
    state.cognito_user_pool_id = data["cognito_user_pool_id"]
    state.cognito_client_id    = data["cognito_client_id"]
    state.cognito_client_secret = data.get("cognito_client_secret", "")
    state.lambda_url            = data.get("lambda_url", "")

    return data


# ---------------------------------------------------------------------------
# ── Cognito authentication ───────────────────────────────────────────────────
# ---------------------------------------------------------------------------

def _cognito_secret_hash(username: str, client_id: str, client_secret: str) -> str:
    """Compute the SECRET_HASH required when the App Client has a secret."""
    msg = (username + client_id).encode("utf-8")
    key = client_secret.encode("utf-8")
    return base64.b64encode(
        hashlib.new("sha256", msg, key).digest()  # not available this way
    ).decode("utf-8")


def _compute_secret_hash(username: str, client_id: str, client_secret: str) -> str:
    import hmac
    msg = (username + client_id).encode("utf-8")
    dig = hmac.new(client_secret.encode("utf-8"), msg, hashlib.sha256).digest()
    return base64.b64encode(dig).decode("utf-8")


def cognito_login(username: str, password: str, state: AppState) -> dict:
    """
    Authenticate with Cognito using USER_PASSWORD_AUTH.
    Automatically includes SECRET_HASH when the app client has a secret configured.
    Requires ALLOW_USER_PASSWORD_AUTH to be enabled in the Cognito app client settings.
    """
    if not COGNITO_AVAILABLE:
        raise ValueError("boto3 not installed.\nRun: pip install boto3")

    client = boto3.client("cognito-idp", region_name=state.region)

    auth_params: dict = {"USERNAME": username, "PASSWORD": password}
    if state.cognito_client_secret:
        auth_params["SECRET_HASH"] = _compute_secret_hash(
            username, state.cognito_client_id, state.cognito_client_secret
        )

    try:
        resp = client.initiate_auth(
            AuthFlow="USER_PASSWORD_AUTH",
            AuthParameters=auth_params,
            ClientId=state.cognito_client_id,
        )
        result = resp["AuthenticationResult"]
        # Store tokens in state so the credential watcher can renew later
        state.id_token      = result.get("IdToken", "")
        state.access_token  = result.get("AccessToken", "")
        state.refresh_token = result.get("RefreshToken", "")
        return result
    except client.exceptions.NotAuthorizedException as exc:
        raise ValueError(f"Incorrect username or password.\nAWS detail: {exc}")
    except client.exceptions.UserNotFoundException as exc:
        raise ValueError(f"User not found.\nAWS detail: {exc}")
    except client.exceptions.UserNotConfirmedException:
        raise ValueError("Account not confirmed. Check your email.")
    except client.exceptions.PasswordResetRequiredException:
        raise ValueError("Password reset required. Check your email.")
    except Exception as exc:
        raise ValueError(f"Authentication error: {type(exc).__name__}: {exc}")


# ---------------------------------------------------------------------------
# ── Credential renewal ───────────────────────────────────────────────────────
# ---------------------------------------------------------------------------

def refresh_cognito_token(state: AppState) -> str:
    """
    Use the Cognito refresh token to get a new IdToken without asking the user
    for their password again.  Updates state.id_token in place.
    Returns the new IdToken.
    """
    if not COGNITO_AVAILABLE:
        raise ValueError("boto3 not installed.")

    client = boto3.client("cognito-idp", region_name=state.region)

    auth_params = {"REFRESH_TOKEN": state.refresh_token}
    if state.cognito_client_secret:
        # SECRET_HASH for refresh uses username="" per AWS docs
        auth_params["SECRET_HASH"] = _compute_secret_hash(
            "", state.cognito_client_id, state.cognito_client_secret
        )

    resp   = client.initiate_auth(
        AuthFlow="REFRESH_TOKEN_AUTH",
        AuthParameters=auth_params,
        ClientId=state.cognito_client_id,
    )
    result = resp["AuthenticationResult"]
    state.id_token    = result["IdToken"]
    state.access_token = result.get("AccessToken", state.access_token)
    return state.id_token


def renew_sts_credentials(state: AppState) -> str:
    """
    Call the Lambda (authenticated with a fresh Cognito IdToken) to get new
    STS credentials.  Overwrites CREDENTIALS_FILE and returns the new
    expiration ISO string.
    """
    if not state.lambda_url:
        raise ValueError("lambda_url not set in credentials file.")

    # First refresh the Cognito token (it may also be near expiry)
    id_token = refresh_cognito_token(state)

    req = urllib.request.Request(
        state.lambda_url,
        data=json.dumps({"project": state.project}).encode(),
        headers={
            "Content-Type": "application/json",
            "Authorization": state.access_token,
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        body = json.loads(resp.read().decode())

    if isinstance(body.get("body"), str):
        payload = json.loads(body["body"])
    else:
        payload = body

    # Overwrite the credentials file with the fresh STS credentials
    existing = ""
    if os.path.isfile(CREDENTIALS_FILE):
        with open(CREDENTIALS_FILE, "r", encoding="utf-8") as f:
            existing = f.read()

    profile_header = f"[{payload['profile']}]"
    if profile_header in existing:
        lines = existing.splitlines()
        out, skip = [], False
        for line in lines:
            if line.strip() == profile_header:
                skip = True
                continue
            if skip and line.strip().startswith("[") and line.strip() != profile_header:
                skip = False
            if not skip:
                out.append(line)
        existing = "\n".join(out).rstrip() + "\n"

    with open(CREDENTIALS_FILE, "w", encoding="utf-8") as f:
        f.write(existing.rstrip() + "\n\n" + payload["config_file_info"].strip() + "\n")

    return payload["expiration"]


# ---------------------------------------------------------------------------
# ── s5cmd helpers ────────────────────────────────────────────────────────────
# ---------------------------------------------------------------------------

def s5cmd_release_info():
    system  = platform.system()
    machine = platform.machine().lower()
    base    = (f"https://github.com/peak/s5cmd/releases/download/"
               f"v{S5CMD_VERSION}/s5cmd_{S5CMD_VERSION}_")
    if system == "Windows":
        arch = "64bit" if ("64" in machine or machine in ("amd64", "x86_64")) else "32bit"
        return base + f"Windows-{arch}.zip", "zip"
    elif system == "Darwin":
        arch = "arm64" if "arm" in machine else "64bit"
        return base + f"macOS-{arch}.tar.gz", "tar"
    else:
        arch = "arm64" if "arm" in machine else "64bit"
        return base + f"Linux-{arch}.tar.gz", "tar"


def ensure_s5cmd(log_callback):
    if os.path.isfile(S5CMD_BIN):
        return
    os.makedirs(APP_DIR, exist_ok=True)
    log_callback("Downloading s5cmd…")
    url, kind = s5cmd_release_info()
    archive_path = os.path.join(APP_DIR, "s5cmd_archive")
    urllib.request.urlretrieve(url, archive_path)
    log_callback("Installing s5cmd…")
    if kind == "zip":
        with zipfile.ZipFile(archive_path) as z:
            z.extractall(APP_DIR)
    else:
        with tarfile.open(archive_path, "r:gz") as t:
            t.extractall(APP_DIR)
    os.remove(archive_path)
    if platform.system() != "Windows":
        os.chmod(S5CMD_BIN, 0o755)
    log_callback("s5cmd ready.")


# ---------------------------------------------------------------------------
# ── S3 listing helpers ────────────────────────────────────────────────────────
# ---------------------------------------------------------------------------

def list_bucket_keys(bucket_path, profile):
    cmd = [S5CMD_BIN, "--profile", profile, "ls", f"s3://{bucket_path}/*"]
    env_vars = os.environ.copy()
    env_vars["AWS_SHARED_CREDENTIALS_FILE"] = CREDENTIALS_FILE
    result = subprocess.run(cmd, capture_output=True, text=True, env=env_vars,
                            creationflags=CREATE_NO_WINDOW)
    counts = {}
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        path  = line.split(maxsplit=3)[3]
        parts = path.split("/")
        group = parts[0] if bucket_path.startswith("neurophindr-analysis") else "/".join(parts[:2])
        key   = f"s3://{bucket_path}/{group}"
        counts[key] = counts.get(key, 0) + 1
    return counts


def list_buckets_parallel(buckets, profile):
    with ThreadPoolExecutor(max_workers=min(4, len(buckets))) as ex:
        return list(ex.map(lambda b: list_bucket_keys(b, profile), buckets))


def best_matching_key(source, keys):
    if not source:
        return None
    candidates = [k for k in keys if source.startswith(k)]
    return max(candidates, key=len) if candidates else None


# ---------------------------------------------------------------------------
# ── Local file counting ──────────────────────────────────────────────────────
# ---------------------------------------------------------------------------

# Extensions and patterns that s5cmd leaves behind on interrupted downloads
_INCOMPLETE_SUFFIXES = (".s5cmd", ".tmp", ".part")

def clean_incomplete_files(local_dir: str) -> int:
    """
    Remove zero-byte files and known s5cmd temp files left by interrupted
    downloads. Returns the number of files removed.
    """
    if not os.path.isdir(local_dir):
        return 0
    removed = 0
    for dirpath, _, files in os.walk(local_dir):
        for fname in files:
            fpath = os.path.join(dirpath, fname)
            try:
                is_temp    = fname.endswith(_INCOMPLETE_SUFFIXES)
                is_empty   = os.path.getsize(fpath) == 0
                if is_temp or is_empty:
                    os.remove(fpath)
                    removed += 1
            except OSError:
                pass
    return removed


def count_local_files(local_dir: str) -> int:
    """Count only non-empty, non-temporary files."""
    if not os.path.isdir(local_dir):
        return 0
    total = 0
    for dirpath, _, files in os.walk(local_dir):
        for fname in files:
            if fname.endswith(_INCOMPLETE_SUFFIXES):
                continue
            fpath = os.path.join(dirpath, fname)
            try:
                if os.path.getsize(fpath) > 0:
                    total += 1
            except OSError:
                pass
    return total


def resolve_local_dir(bucket: str, local_dest: str, key: str, project: str) -> str:
    if bucket.startswith("neurophindr-analysis"):
        group = key.rsplit("/", 1)[-1]
    else:
        group = "/".join(key.split("/")[-2:])
    return os.path.join(local_dest, project, group)


# ---------------------------------------------------------------------------
# ── Window 1: Load config file ───────────────────────────────────────────────
# ---------------------------------------------------------------------------

class LoadConfigWindow(tk.Tk):
    """
    First screen: user selects the JSON credentials file.
    Populates AppState and closes so the login window can open.
    """
    def __init__(self, state: AppState):
        super().__init__()
        self.state    = state
        self.selected = False

        self.title("S3 Bulk Downloader – Select credentials")
        self.geometry("420x200")
        self.resizable(False, False)

        tk.Label(self, text="S3 Bulk Downloader",
                 font=("Helvetica", 14, "bold"), fg="#1e3a5f").pack(pady=(28, 4))
        tk.Label(self, text="Select your credentials file to continue",
                 font=("Helvetica", 9), fg="#555").pack()

        self.error_var = tk.StringVar()
        tk.Label(self, textvariable=self.error_var, fg="#c0392b",
                 font=("Helvetica", 8), wraplength=380).pack(pady=(6, 0))

        tk.Button(
            self, text="Select downloaded file (.json)",
            command=self._pick, bg="#B6D6F0", fg="black", width=36,
        ).pack(pady=20)

    def _pick(self):
        path = filedialog.askopenfilename(
            title="Select credentials file",
            filetypes=[("JSON", "*.json")],
        )
        if not path:
            return
        try:
            load_credentials_file(path, self.state)   # fills self.state in-place
            self.selected = True
            self.destroy()
        except Exception as exc:
            self.error_var.set(f"Error: {exc}")


# ---------------------------------------------------------------------------
# ── Window 2: Cognito login ──────────────────────────────────────────────────
# ---------------------------------------------------------------------------

class LoginWindow(tk.Tk):
    """
    Second screen: username + password, authenticated against the Cognito
    pool read from AppState (populated by LoadConfigWindow).
    """
    def __init__(self, state: AppState):
        super().__init__()
        self.state         = state
        self.authenticated = False

        self.title("S3 Bulk Downloader – Login")
        self.geometry("360x270")
        self.resizable(False, False)

        tk.Label(self, text="S3 Bulk Downloader",
                 font=("Helvetica", 14, "bold"), fg="#1e3a5f").pack(pady=(28, 4))
        tk.Label(self, text="Sign in with your account",
                 font=("Helvetica", 9), fg="#555").pack()

        frame = tk.Frame(self, padx=30, pady=14)
        frame.pack(fill="both", expand=True)

        tk.Label(frame, text="Username:", anchor="w").grid(row=0, column=0, sticky="w", pady=5)
        self.username_var = tk.StringVar()
        tk.Entry(frame, textvariable=self.username_var, width=28).grid(row=0, column=1, padx=6)

        tk.Label(frame, text="Password:", anchor="w").grid(row=1, column=0, sticky="w", pady=5)
        self.password_var = tk.StringVar()
        pwd_entry = tk.Entry(frame, textvariable=self.password_var, show="•", width=28)
        pwd_entry.grid(row=1, column=1, padx=6)
        pwd_entry.bind("<Return>", lambda _: self._do_login())

        self.error_var = tk.StringVar()
        tk.Label(frame, textvariable=self.error_var, fg="#c0392b",
                 wraplength=280, font=("Helvetica", 8)).grid(
            row=2, column=0, columnspan=2, pady=(4, 0))

        self.login_btn = tk.Button(
            frame, text="Sign in", command=self._do_login,
            bg="#627BC1", fg="white", width=22, relief="flat",
        )
        self.login_btn.grid(row=3, column=0, columnspan=2, pady=12)

    def _do_login(self):
        username = self.username_var.get().strip()
        password = self.password_var.get()
        if not username or not password:
            self.error_var.set("Please enter username and password.")
            return
        self.login_btn.config(state="disabled", text="Signing in…")
        self.error_var.set("")
        self.update_idletasks()
        threading.Thread(target=self._auth_thread,
                         args=(username, password), daemon=True).start()

    def _auth_thread(self, username, password):
        try:
            cognito_login(username, password, self.state)   # uses pool/client from state
            self.authenticated = True
            self.after(0, self.destroy)
        except ValueError as exc:
            msg = str(exc)
            self.after(0, lambda m=msg: self._on_error(m))

    def _on_error(self, msg):
        self.error_var.set(msg)
        self.login_btn.config(state="normal", text="Sign in")


# ---------------------------------------------------------------------------
# ── Window 3: Main download application ─────────────────────────────────────
# ---------------------------------------------------------------------------

class App(tk.Tk):
    def __init__(self, state: AppState):
        super().__init__()
        self.state = state

        self.title("S3 Bulk Downloader")
        self.geometry("640x680")
        self.resizable(False, False)

        pad = {"padx": 10, "pady": 5}

        self.select_filebtn = tk.Button(
            self, text="Select downloaded file (.json)",
            command=self._pick_config_file, bg="#B6D6F0", fg="black", width=40,
        )
        self.select_filebtn.grid(row=0, column=0, columnspan=2,
                                 padx=10, pady=10, sticky="we")

        self.create_label("Region AWS:", 1, "lbl_region",  pad)
        self.create_label("Profile AWS:", 2, "lbl_profile", pad)
        self.create_label("Environment:", 3, "lbl_env",     pad)
        self.create_label("Project:",     4, "lbl_project", pad)

        tk.Label(self, text="Destination:").grid(row=5, column=0, sticky="w", **pad)
        dest_frame = tk.Frame(self)
        dest_frame.grid(row=5, column=1, **pad)
        self.dest = tk.Entry(dest_frame, width=32)
        self.dest.insert(0, os.path.join(os.path.expanduser("~"), "Downloads", "s3-data"))
        self.dest.pack(side="left")
        tk.Button(dest_frame, text="...", command=self._pick_dest, width=3).pack(side="left", padx=3)
        self.dest_btn = dest_frame.winfo_children()[-1]

        self.start_btn = tk.Button(
            self, text="Download", command=self.start,
            bg="#627BC1", fg="white", width=20,
        )
        self.start_btn.grid(row=6, column=0, columnspan=2, pady=15)


        self.progress = ttk.Progressbar(self, length=600, mode="determinate")
        self.progress.grid(row=7, column=0, columnspan=2, padx=10)

        self.progress_label = tk.Label(self, text="0 / 0 Files (0%)", anchor="w")
        self.progress_label.grid(row=8, column=0, columnspan=2, sticky="w", padx=10)

        self.status_lbl = tk.Label(self, text="Ready.", anchor="w", fg="#444")
        self.status_lbl.grid(row=9, column=0, columnspan=2, sticky="w", padx=10, pady=5)

        tk.Label(self, text="Files:").grid(row=10, column=0, sticky="w", padx=10)

        tree_frame = tk.Frame(self)
        tree_frame.grid(row=11, column=0, columnspan=2, padx=10, pady=5, sticky="nsew")

        self.tree = ttk.Treeview(tree_frame, columns=("status",),
                                 show="tree headings", height=14)
        self.tree.heading("#0",     text="File")
        self.tree.heading("status", text="Status")
        self.tree.column("#0",      width=440)
        self.tree.column("status",  width=140, anchor="center")

        scrollbar = ttk.Scrollbar(tree_frame, orient="vertical",
                                  command=self._on_scrollbar_move)
        self.tree.configure(yscrollcommand=scrollbar.set)
        self.tree.bind("<MouseWheel>",
                       lambda e: self.after(10, self.reposition_all_progressbars))
        self.tree.bind("<Button-4>",
                       lambda e: self.after(10, self.reposition_all_progressbars))
        self.tree.bind("<Button-5>",
                       lambda e: self.after(10, self.reposition_all_progressbars))
        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        self.tree.tag_configure("done",        foreground="#16a34a")
        self.tree.tag_configure("pending",     foreground="#888")
        self.tree.tag_configure("downloading", foreground="#000000")
        self.tree.tag_configure("error",       foreground="#dc2626")
        self.tree.tag_configure("local",       foreground="#2563eb")

        self._row_by_key           = {}
        self._progressbars         = {}
        self._group_totals         = {}
        self._ui_lock              = threading.Lock()
        self._pending_downloading  = set()
        self._pending_done         = set()
        self._pending_error        = {}
        self._pending_progress     = None
        self._pending_group_progress = {}
        self._flush_scheduled      = False
        self._active_proc          = None
        self._download_finished    = threading.Event()  # set when download ends

        # Pre-fill labels now that all widgets exist
        self._fill_labels()

        self.protocol("WM_DELETE_WINDOW", self._on_close)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _fill_labels(self):
        self._set_readonly_entry(self.lbl_region,  self.state.region)
        self._set_readonly_entry(self.lbl_profile, self.state.profile)
        self._set_readonly_entry(self.lbl_env,     self.state.environment)
        self._set_readonly_entry(self.lbl_project, self.state.project)


    def _pick_config_file(self):
        """Allow re-loading credentials from a new file without restarting."""
        path = filedialog.askopenfilename(
            title="Select credentials file",
            filetypes=[("JSON", "*.json")],
        )
        if not path:
            return
        try:
            load_credentials_file(path, self.state)
            self._fill_labels()
            self.set_status("Credentials updated.")
        except Exception as exc:
            messagebox.showerror("Error", f"Invalid file: {exc}")

    def _pick_dest(self):
        d = filedialog.askdirectory()
        if d:
            self.dest.delete(0, tk.END)
            self.dest.insert(0, d)

    def set_status(self, msg):
        self.status_lbl.config(text=msg)

    def create_label(self, text, row, attr_name, pad):
        tk.Label(self, text=text).grid(row=row, column=0, sticky="w", **pad)
        entry = tk.Entry(self, width=40, state="readonly")
        entry.grid(row=row, column=1, **pad)
        setattr(self, attr_name, entry)

    @staticmethod
    def _set_readonly_entry(entry, value):
        entry.config(state="normal")
        entry.delete(0, tk.END)
        entry.insert(0, value or "")
        entry.config(state="readonly")

    def _on_close(self):
        if self._active_proc and self._active_proc.poll() is None:
            if not messagebox.askyesno(
                "Download in progress",
                "A download is still running. Closing now will stop it. Close anyway?",
            ):
                return
            self._kill_active_proc()
        self.destroy()

    def _kill_active_proc(self):
        proc = self._active_proc
        if not proc or proc.poll() is not None:
            return
        try:
            if platform.system() == "Windows":
                subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                               creationflags=CREATE_NO_WINDOW)
            else:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Tree / progressbar management
    # ------------------------------------------------------------------

    def reset_tree(self):
        for pbar in self._progressbars.values():
            pbar.destroy()
        self._progressbars = {}
        self._group_totals = {}
        self.tree.delete(*self.tree.get_children())
        self._row_by_key = {}

    def add_file_row(self, key, total_files, local_count=0):
        self._group_totals[key] = total_files
        if local_count >= total_files:
            row_id = self.tree.insert("", "end", text=key,
                                      values=("✓ Completed",), tags=("done",))
            self._row_by_key[key] = row_id
            return
        row_id = self.tree.insert("", "end", text=key,
                                  values=("⏳ Pending",), tags=("pending",))
        self._row_by_key[key] = row_id
        if local_count > 0:
            pbar = ttk.Progressbar(self.tree, length=100, mode="determinate",
                                   maximum=max(total_files, 1), value=local_count)
            self._progressbars[row_id] = pbar
            self._place_progressbar(row_id)
            self.tree.item(row_id, values=("",), tags=("downloading",))

    def _on_scrollbar_move(self, *args):
        self.tree.yview(*args)
        self.reposition_all_progressbars()

    def _place_progressbar(self, row_id):
        pbar = self._progressbars.get(row_id)
        if not pbar:
            return
        bbox = self.tree.bbox(row_id, column="status")
        if not bbox:
            pbar.place_forget()
            return
        x, y, width, height = bbox
        pbar.place(x=x, y=y, width=width, height=height)

    def reposition_all_progressbars(self):
        for row_id in list(self._progressbars.keys()):
            self._place_progressbar(row_id)

    def _remove_progressbar(self, row_id):
        pbar = self._progressbars.pop(row_id, None)
        if pbar:
            pbar.place_forget()
            pbar.destroy()

    def mark_downloading(self, key):
        row_id = self._row_by_key.get(key)
        if row_id and row_id not in self._progressbars:
            total_files = self._group_totals.get(key, 1)
            pbar = ttk.Progressbar(self.tree, length=100, mode="determinate",
                                   maximum=max(total_files, 1))
            self._progressbars[row_id] = pbar
            self._place_progressbar(row_id)
        if row_id:
            self.tree.item(row_id, values=("",), tags=("downloading",))

    def mark_done(self, key):
        row_id = self._row_by_key.get(key)
        if row_id:
            self._remove_progressbar(row_id)
            self.tree.item(row_id, values=("✓ Completed",), tags=("done",))

    def mark_error(self, key, msg=""):
        row_id = self._row_by_key.get(key)
        if row_id:
            self._remove_progressbar(row_id)
            self.tree.item(row_id, values=("✗ Error",), tags=("error",))

    def update_group_progress(self, key, completed, total):
        row_id = self._row_by_key.get(key)
        pbar   = self._progressbars.get(row_id)
        if pbar:
            pbar["maximum"] = max(total, 1)
            pbar["value"]   = completed

    def update_progress(self, done, total):
        pct = int((done / total) * 100) if total else 0
        self.progress["value"] = pct
        self.progress_label.config(text=f"{done} / {total} files ({pct}%)")

    # ------------------------------------------------------------------
    # Batched UI plumbing
    # ------------------------------------------------------------------

    def queue_downloading(self, key):
        with self._ui_lock:
            self._pending_downloading.add(key)
            self._schedule_flush_locked()

    def queue_done(self, key):
        with self._ui_lock:
            self._pending_downloading.discard(key)
            self._pending_done.add(key)
            self._schedule_flush_locked()

    def queue_error(self, key, msg=""):
        with self._ui_lock:
            self._pending_downloading.discard(key)
            self._pending_error[key] = msg
            self._schedule_flush_locked()

    def queue_progress(self, done, total):
        with self._ui_lock:
            self._pending_progress = (done, total)
            self._schedule_flush_locked()

    def queue_group_progress(self, key, completed, total):
        with self._ui_lock:
            self._pending_group_progress[key] = (completed, total)
            self._schedule_flush_locked()

    def _schedule_flush_locked(self):
        if not self._flush_scheduled:
            self._flush_scheduled = True
            self.after(UI_FLUSH_INTERVAL_MS, self._flush_ui)

    def _flush_ui(self):
        with self._ui_lock:
            downloading    = self._pending_downloading
            done           = self._pending_done
            errors         = self._pending_error
            progress       = self._pending_progress
            group_progress = self._pending_group_progress
            self._pending_downloading    = set()
            self._pending_done           = set()
            self._pending_error          = {}
            self._pending_progress       = None
            self._pending_group_progress = {}
            self._flush_scheduled        = False

        last_row = None
        for key, (completed, total) in group_progress.items():
            self.update_group_progress(key, completed, total)
        for key in downloading:
            self.mark_downloading(key)
            last_row = self._row_by_key.get(key)
        for key in done:
            self.mark_done(key)
            last_row = self._row_by_key.get(key)
        for key, msg in errors.items():
            self.mark_error(key, msg)
            last_row = self._row_by_key.get(key)
        if last_row:
            self.tree.see(last_row)
            self.reposition_all_progressbars()
        if progress:
            self.update_progress(*progress)

    # ------------------------------------------------------------------
    # Credential watcher
    # ------------------------------------------------------------------

    def _start_credential_watcher(self, expiration_iso: str):
        """
        Background thread that renews STS credentials ~5 minutes before they
        expire by calling the Lambda with a refreshed Cognito token.
        Runs until self._download_finished is set.
        """
        def watcher():
            current_expiry = expiration_iso
            while not self._download_finished.wait(timeout=60):  # check every minute
                try:
                    expiry = datetime.fromisoformat(current_expiry)
                    if expiry.tzinfo is None:
                        expiry = expiry.replace(tzinfo=timezone.utc)
                    remaining = (expiry - datetime.now(timezone.utc)).total_seconds()
                    if remaining < 300:  # less than 5 minutes left
                        self.set_status("Renewing credentials…")
                        current_expiry = renew_sts_credentials(self.state)
                        self.set_status("Credentials renewed.")
                except Exception as exc:
                    # Non-fatal: log and keep trying next cycle
                    self.set_status(f"Warning: credential renewal failed: {exc}")

        threading.Thread(target=watcher, daemon=True).start()

    # ------------------------------------------------------------------
    # Download flow
    # ------------------------------------------------------------------

    def start(self):
        # Read live values from the labels (in case file was reloaded)
        region  = self.lbl_region.get().strip()
        profile = self.lbl_profile.get().strip()
        env     = self.lbl_env.get().strip()
        dest    = self.dest.get().strip()
        project = self.lbl_project.get().strip()

        if not all([region, profile, env, dest, project]):
            messagebox.showerror("Error", "Fill all fields.")
            return

        self.start_btn.config(state="disabled")
        self.select_filebtn.config(state="disabled")
        self.dest_btn.config(state="disabled")
        self.dest.config(state="readonly")

        self.reset_tree()
        self.update_progress(0, 0)
        threading.Thread(
            target=self.run_download,
            args=(region, profile, env, dest, project),
            daemon=True,
        ).start()

    def run_download(self, region, profile, env, dest, project):
        self._download_finished.clear()
        # Start credential watcher using the STS expiration from the loaded JSON
        expiration_iso = getattr(self.state, "_sts_expiration", "")
        if expiration_iso and self.state.lambda_url:
            self._start_credential_watcher(expiration_iso)
        try:
            ensure_s5cmd(self.set_status)

            buckets = [
                f"neurophindr-analysis-{env}/{project}",
                f"neurophindr-output-{env}/{project}",
            ]
            dests = [
                os.path.join(dest, f"analysis-{env}"),
                os.path.join(dest, f"output-{env}"),
            ]

            self.after(0, lambda: (
                self.progress.config(mode="indeterminate"),
                self.progress.start(10),
            ))
            self.set_status(f"Listing files from {len(buckets)} bucket(s)…")
            keys_per_bucket = list_buckets_parallel(buckets, profile)
            self.after(0, lambda: (
                self.progress.stop(),
                self.progress.config(mode="determinate"),
            ))

            all_keys: dict[str, int] = {}
            for counts in keys_per_bucket:
                all_keys.update(counts)

            # Clean up incomplete files from previous interrupted downloads,
            # then count only the valid completed files.
            self.set_status("Checking local files…")
            local_counts: dict[str, int] = {}
            for bucket, local_dest in zip(buckets, dests):
                bucket_keys = keys_per_bucket[buckets.index(bucket)]
                for key in bucket_keys:
                    local_dir = resolve_local_dir(bucket, local_dest, key, project)
                    removed   = clean_incomplete_files(local_dir)
                    if removed:
                        self.set_status(f"Removed {removed} incomplete file(s) in {os.path.basename(local_dir)}")
                    local_counts[key] = count_local_files(local_dir)

            already_done = sum(min(local_counts.get(k, 0), v) for k, v in all_keys.items())
            total        = sum(all_keys.values())

            def populate_rows():
                for k, remote_count in all_keys.items():
                    self.add_file_row(k, remote_count, local_count=local_counts.get(k, 0))
                self.update_progress(already_done, total)

            self.after(0, populate_rows)
            time.sleep(0.15)

            done = already_done
            for bucket, local_dest, keys in zip(buckets, dests, keys_per_bucket):
                keys_to_download = {k: v for k, v in keys.items()
                                    if local_counts.get(k, 0) < v}
                if not keys_to_download:
                    self.set_status(f"{bucket}: all files already present.")
                    continue
                self.set_status(f"Downloading {bucket}…")
                os.makedirs(local_dest, exist_ok=True)
                done = self.sync_bucket(bucket, local_dest, profile, region,
                                        keys_to_download, done, total, project, local_counts)

            self.update_progress(total, total)
            self.set_status("Download completed.")
            messagebox.showinfo("Done", "Download completed.")

        except Exception as exc:
            self.set_status("Error.")
            messagebox.showerror("Error", str(exc))
        finally:
            self._download_finished.set()   # stop the credential watcher thread
            self.start_btn.config(state="normal")
            self.select_filebtn.config(state="normal")
            self.dest_btn.config(state="normal")
            self.dest.config(state="normal")

    def sync_bucket(self, bucket, local_dest, profile, region,
                    keys, done, total, project, local_counts):
        batch_path = os.path.join(local_dest, f"_s5cmd_batch_{uuid.uuid4().hex}.txt")
        completed_for_key = {k: local_counts.get(k, 0) for k in keys}

        with open(batch_path, "w", encoding="utf-8") as f:
            for key in keys:
                group = (key.rsplit("/", 1)[-1]
                         if bucket.startswith("neurophindr-analysis")
                         else "/".join(key.split("/")[-2:]))
                target_dir = os.path.join(local_dest, project, group)
                os.makedirs(target_dir, exist_ok=True)
                f.write(f'sync --size-only --source-region {region} "{key}/*" "{target_dir}/"\n')

        cmd      = [S5CMD_BIN, "--profile", profile, "run", batch_path]
        env_vars = os.environ.copy()
        env_vars["AWS_SHARED_CREDENTIALS_FILE"] = CREDENTIALS_FILE
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1, env=env_vars, universal_newlines=True,
            creationflags=CREATE_NO_WINDOW,
        )
        self._active_proc = proc

        error_keys = set()
        for line in proc.stdout:
            line = line.strip()
            if not line:
                continue
            if line.startswith("cp ") or line.startswith("download "):
                parts   = line.split()
                source  = next((p for p in parts if p.startswith("s3://")), None)
                matched = best_matching_key(source, keys)
                if matched:
                    done += 1
                    completed_for_key[matched] += 1
                    expected = keys.get(matched, float("inf"))
                    self.queue_group_progress(
                        matched, completed_for_key[matched],
                        expected if expected != float("inf") else completed_for_key[matched],
                    )
                    self.queue_downloading(matched)
                    self.queue_progress(done, total)
                    if completed_for_key[matched] >= expected and matched not in error_keys:
                        self.queue_done(matched)
            elif line.startswith("ERROR"):
                parts   = line.split()
                source  = next((p for p in parts if p.startswith("s3://")), None)
                matched = best_matching_key(source, keys)
                if matched:
                    error_keys.add(matched)
                    self.queue_error(matched, line)

        proc.wait()
        proc.stdout.close()
        self._active_proc = None
        os.remove(batch_path)

        if proc.returncode != 0:
            raise RuntimeError(f"s5cmd failed on bucket {bucket} (code {proc.returncode})")

        for key, expected_count in keys.items():
            if key in error_keys:
                continue
            seen = completed_for_key[key]
            if seen == 0:
                self.queue_group_progress(key, expected_count, expected_count)
                self.queue_done(key)
                done += expected_count
                self.queue_progress(done, total)
            elif seen < expected_count:
                self.queue_error(key, f"Expected {expected_count} files, only saw {seen}")

        return done


# ---------------------------------------------------------------------------
# ── Entry point ──────────────────────────────────────────────────────────────
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    state = AppState()   # single object shared across all three windows

    # Step 1 – select JSON file (fills state)
    w1 = LoadConfigWindow(state)
    w1.mainloop()
    if not w1.selected:
        sys.exit(0)

    # Step 2 – Cognito login (uses pool/client from state)
    w2 = LoginWindow(state)
    w2.mainloop()
    if not w2.authenticated:
        sys.exit(0)

    # Step 3 – main downloader (reads region/profile/etc. from state)
    w3 = App(state)
    w3.mainloop()