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
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from concurrent.futures import ThreadPoolExecutor
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


DECRYPTION_PASSPHRASE = "testpassphrase123"

CREDENTIALS_FILE = os.path.join(os.path.expanduser("~"), ".credentials-file")
S5CMD_VERSION = "2.2.2"
APP_DIR = os.path.join(os.path.expanduser("~"), ".s3downloader")
S5CMD_BIN = os.path.join(APP_DIR, "s5cmd.exe" if platform.system() == "Windows" else "s5cmd")

# Batch UI updates instead of scheduling a Tk callback per downloaded file.
UI_FLUSH_INTERVAL_MS = 150
CREATE_NO_WINDOW = 0x08000000 if platform.system() == "Windows" else 0

def decrypt_payload(encrypted_obj, passphrase):
    salt = base64.b64decode(encrypted_obj["salt"])
    iv = base64.b64decode(encrypted_obj["iv"])
    auth_tag = base64.b64decode(encrypted_obj["authTag"])
    ciphertext = base64.b64decode(encrypted_obj["ciphertext"])

    key = hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf-8"), salt, 100000, dklen=32)
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(iv, ciphertext + auth_tag, None)
    return json.loads(plaintext.decode("utf-8"))


def s5cmd_release_info():
    system = platform.system()
    machine = platform.machine().lower()
    base = f"https://github.com/peak/s5cmd/releases/download/v{S5CMD_VERSION}/s5cmd_{S5CMD_VERSION}_"

    if system == "Windows":
        arch = "64bit" if "64" in machine or machine in ("amd64", "x86_64") else "32bit"
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
    log_callback("Descargando s5cmd...")
    url, kind = s5cmd_release_info()
    archive_path = os.path.join(APP_DIR, "s5cmd_archive")
    urllib.request.urlretrieve(url, archive_path)

    log_callback("Instalando s5cmd...")
    if kind == "zip":
        with zipfile.ZipFile(archive_path) as z:
            z.extractall(APP_DIR)
    else:
        with tarfile.open(archive_path, "r:gz") as t:
            t.extractall(APP_DIR)
    os.remove(archive_path)

    if platform.system() != "Windows":
        os.chmod(S5CMD_BIN, 0o755)

    log_callback("s5cmd listo.")


def load_credentials_file(json_path):
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
    required = ["environment", "region", "profile", "project", "config_file_info", "expiration"]
    missing = [k for k in required if k not in data]
    if missing:
        raise ValueError(f"json file corrupted, download it again: {', '.join(missing)}")

    expiration = datetime.fromisoformat(data["expiration"])
    if expiration < datetime.now(timezone.utc):
        raise ValueError("Credentials have expired. Download the json file again")

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

    return data


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
        path = line.split(maxsplit=3)[3]
        parts = path.split('/')
        if bucket_path.startswith("neurophindr-analysis"):
            group = parts[0]
        else:
            group = '/'.join(parts[:2])  # grupo/mod
        key = f"s3://{bucket_path}/{group}"
        counts[key] = counts.get(key, 0) + 1
    return counts


def list_buckets_parallel(buckets, profile):
    """Run list_bucket_keys for every bucket concurrently instead of serially."""
    with ThreadPoolExecutor(max_workers=min(4, len(buckets))) as ex:
        results = list(ex.map(lambda b: list_bucket_keys(b, profile), buckets))
    return results


def best_matching_key(source, keys):
    """
    Return the longest key that is a prefix of `source`.

    Using the *first* match (in dict insertion order) is a bug: if keys
    "s3://bucket/run" and "s3://bucket/run2" both exist, a file under
    "run2/..." would incorrectly match "run" first. The longest-prefix
    match is the only one that's actually unambiguous.
    """
    if not source:
        return None
    candidates = [k for k in keys if source.startswith(k)]
    if not candidates:
        return None
    return max(candidates, key=len)


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("S3 Bulk Downloader")
        self.geometry("640x680")
        self.resizable(False, False)

        pad = {"padx": 10, "pady": 5}

        self.select_filebtn = tk.Button(self, text="Select downloaded file (.json)",
                  command=self.pick_config_file, bg="#B6D6F0", fg="black", width=40
                  )
        self.select_filebtn.grid(row=0, column=0, columnspan=2, padx=10, pady=10, sticky="we")

        self.create_label("Region AWS:", 1, "region", pad)
        self.create_label("Profile AWS:", 2, "profile", pad)
        self.create_label("Environment:", 3, "env", pad)
        self.create_label("Project:", 4, "project", pad)

        tk.Label(self, text="Destination:").grid(row=5, column=0, sticky="w", **pad)
        dest_frame = tk.Frame(self)
        dest_frame.grid(row=5, column=1, **pad)
        self.dest = tk.Entry(dest_frame, width=32)
        self.dest.insert(0, os.path.join(os.path.expanduser("~"), "Downloads", "s3-data"))
        self.dest.pack(side="left")

        self.dest_btn = tk.Button(dest_frame, text="...", command=self.pick_dest, width=3)
        self.dest_btn.pack(side="left", padx=3)

        self.start_btn = tk.Button(self, text="Download", command=self.start, bg="#627BC1", fg="white", width=20)
        self.start_btn.grid(row=6, column=0, columnspan=2, pady=15)

        self.progress = ttk.Progressbar(self, length=600, mode="determinate")
        self.progress.grid(row=7, column=0, columnspan=2, padx=10)

        self.progress_label = tk.Label(self, text="0 / 0 Files (0%)", anchor="w")
        self.progress_label.grid(row=8, column=0, columnspan=2, sticky="w", padx=10)

        self.status = tk.Label(self, text="Listo.", anchor="w", fg="#444")
        self.status.grid(row=9, column=0, columnspan=2, sticky="w", padx=10, pady=5)

        tk.Label(self, text="Files:").grid(row=10, column=0, sticky="w", padx=10)

        tree_frame = tk.Frame(self)
        tree_frame.grid(row=11, column=0, columnspan=2, padx=10, pady=5, sticky="nsew")

        self.tree = ttk.Treeview(tree_frame, columns=("status",), show="tree headings", height=14)
        self.tree.heading("#0", text="File")
        self.tree.heading("status", text="Status")
        self.tree.column("#0", width=440)
        self.tree.column("status", width=120, anchor="center")
        scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        self.tree.tag_configure("done", foreground="#16a34a")
        self.tree.tag_configure("pending", foreground="#888")
        self.tree.tag_configure("error", foreground="#dc2626")

        self._row_by_key = {}

        # --- UI update batching state ---
        # Instead of scheduling a Tk `after` callback for every single
        # downloaded file (which can flood the event queue on large
        # transfers), workers stage pending UI changes here and a single
        # periodic flush applies them all at once.
        self._ui_lock = threading.Lock()
        self._pending_downloading = set()
        self._pending_done = set()
        self._pending_error = {}
        self._pending_progress = None  # (done, total)
        self._flush_scheduled = False

    def create_label(self, text, row, attr_name, pad):
        tk.Label(self, text=text).grid(row=row, column=0, sticky="w", **pad)
        entry = tk.Entry(self, width=40, state="readonly")
        entry.grid(row=row, column=1, **pad)
        setattr(self, attr_name, entry)

    def pick_config_file(self):
        path = filedialog.askopenfilename(
            title="Select credentials file",
            filetypes=[("JSON", "*.json")],
        )
        if not path:
            return
        try:
            data = load_credentials_file(path)
        except Exception as e:
            messagebox.showerror("Error", f"Invalid file: {e}")
            return

        self._set_readonly_entry(self.region, data["region"])
        self._set_readonly_entry(self.profile, data["profile"])
        self._set_readonly_entry(self.env, data["environment"])
        self._set_readonly_entry(self.project, data.get("project", ""))

        self.set_status("Credentials ready")

    @staticmethod
    def _set_readonly_entry(entry, value):
        entry.config(state="normal")
        entry.delete(0, tk.END)
        entry.insert(0, value)
        entry.config(state="readonly")

    def pick_dest(self):
        d = filedialog.askdirectory()
        if d:
            self.dest.delete(0, tk.END)
            self.dest.insert(0, d)

    def set_status(self, msg):
        self.status.config(text=msg)

    def reset_tree(self):
        self.tree.delete(*self.tree.get_children())
        self._row_by_key = {}

    def add_file_row(self, key):
        row_id = self.tree.insert("", "end", text=key, values=("⏳ Pending",), tags=("pending",))
        self._row_by_key[key] = row_id

    def mark_downloading(self, key):
        row_id = self._row_by_key.get(key)
        if row_id:
            self.tree.item(row_id, values=("Downloading...",), tags=("downloading",))

    def mark_done(self, key):
        row_id = self._row_by_key.get(key)
        if row_id:
            self.tree.item(row_id, values=("✓ Completed",), tags=("done",))

    def mark_error(self, key, msg=""):
        row_id = self._row_by_key.get(key)
        if row_id:
            self.tree.item(row_id, values=("✗ Error",), tags=("error",))

    def update_progress(self, done, total):
        pct = int((done / total) * 100) if total else 0
        self.progress["value"] = pct
        self.progress_label.config(text=f"{done} / {total} files ({pct}%)")

    # ------------------------------------------------------------------
    # Batched UI update plumbing.
    #
    # Worker threads call `queue_*` methods (thread-safe, no Tk calls),
    # which just stage state under a lock. A single `after`-scheduled
    # `_flush_ui` call runs periodically and applies everything in one
    # pass, then reschedules itself only while there's an active
    # download. This bounds the number of Tk operations to roughly
    # (download time / UI_FLUSH_INTERVAL_MS) instead of one per file.
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

    def _schedule_flush_locked(self):
        # Caller already holds self._ui_lock.
        if not self._flush_scheduled:
            self._flush_scheduled = True
            self.after(UI_FLUSH_INTERVAL_MS, self._flush_ui)

    def _flush_ui(self):
        with self._ui_lock:
            downloading = self._pending_downloading
            done = self._pending_done
            errors = self._pending_error
            progress = self._pending_progress
            self._pending_downloading = set()
            self._pending_done = set()
            self._pending_error = {}
            self._pending_progress = None
            self._flush_scheduled = False

        last_row = None
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
        if progress:
            self.update_progress(*progress)

    def start(self):
        region = self.region.get().strip()
        profile = self.profile.get().strip()
        env = self.env.get().strip()
        dest = self.dest.get().strip()
        project = self.project.get().strip()

        if not all([region, profile, env, dest, project]):
            messagebox.showerror("Error", "Fill all fields.")
            return

        self.start_btn.config(state="disabled")
        self.select_filebtn.config(state="disabled")
        self.dest_btn.config(state="disabled")

        self.dest.config(state="readonly")

        self.reset_tree()
        self.update_progress(0, 0)
        threading.Thread(target=self.run_download, args=(region, profile, env, dest, project), daemon=True).start()

    def run_download(self, region, profile, env, dest, project):
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

            self.after(0, lambda: (self.progress.config(mode="indeterminate"), self.progress.start(10)))
            self.set_status(f"Listing files from {len(buckets)} bucket(s)...")
            
            keys_per_bucket = list_buckets_parallel(buckets, profile)
            self.after(0, lambda: (self.progress.stop(), self.progress.config(mode="determinate")))

            all_keys = {}
            for counts in keys_per_bucket:
                all_keys.update(counts)
            for k in all_keys:
                self.add_file_row(k)

            total = sum(all_keys.values())
            done = 0
            self.update_progress(done, total)

            for bucket, local_dest, keys in zip(buckets, dests, keys_per_bucket):
                self.set_status(f"Downloading {bucket}...")
                os.makedirs(local_dest, exist_ok=True)
                done = self.sync_bucket(bucket, local_dest, profile, region, keys, done, total, project)

            self.update_progress(total, total)
            self.set_status("Download completed.")
            messagebox.showinfo("Done", "Download completed.")
        except Exception as e:
            self.set_status("Error.")
            messagebox.showerror("Error", str(e))
        finally:
            self.start_btn.config(state="normal")
            self.select_filebtn.config(state="normal")
            self.dest_btn.config(state="normal")
            self.dest.config(state="normal")

    def sync_bucket(self, bucket, local_dest, profile, region, keys, done, total, project):
        batch_path = os.path.join(local_dest, f"_s5cmd_batch_{uuid.uuid4().hex}.txt")
        completed_for_key = {k: 0 for k in keys}

        with open(batch_path, "w", encoding="utf-8") as f:
            for key in keys:
                if bucket.startswith("neurophindr-analysis"):
                    group = key.rsplit("/", 1)[-1]
                else:
                    group = "/".join(key.split("/")[-2:])
                target_dir = os.path.join(local_dest, project, group)
                os.makedirs(target_dir, exist_ok=True)
                f.write(f'sync --source-region {region} "{key}/*" "{target_dir}/"\n')

        cmd = [S5CMD_BIN, "--profile", profile, "run", batch_path]
        env_vars = os.environ.copy()
        env_vars["AWS_SHARED_CREDENTIALS_FILE"] = CREDENTIALS_FILE
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1, env=env_vars, universal_newlines=True,
            creationflags=CREATE_NO_WINDOW,
        )

        error_keys = set()
        for line in proc.stdout:
            line = line.strip()
            if not line:
                continue
            if line.startswith("cp ") or line.startswith("download "):
                parts = line.split()
                source = next((p for p in parts if p.startswith("s3://")), None)
                matched = best_matching_key(source, keys)
                if matched:
                    done += 1
                    completed_for_key[matched] += 1
                    self.queue_downloading(matched)
                    self.queue_progress(done, total)
                    expected = keys.get(matched, float("inf"))
                    if completed_for_key[matched] >= expected and matched not in error_keys:
                        self.queue_done(matched)
            elif line.startswith("ERROR"):
                parts = line.split()
                source = next((p for p in parts if p.startswith("s3://")), None)
                matched = best_matching_key(source, keys)
                if matched:
                    error_keys.add(matched)
                    self.queue_error(matched, line)

        proc.wait()
        proc.stdout.close()
        os.remove(batch_path)

        if proc.returncode != 0:
            raise RuntimeError(f"s5cmd falló en bucket {bucket} (code {proc.returncode})")

        # Fallback for keys s5cmd never reported a line for (e.g. an empty
        # "group" with zero matching objects, or output s5cmd formats in a
        # way our line parser didn't recognize). We only trust this path
        # when NO files were reported for that key at all; if some files
        # came through but fewer than expected, we leave it as an error
        # rather than silently marking it done and inflating `done` past
        # what was actually verified.
        for key, expected_count in keys.items():
            if key in error_keys:
                continue
            seen = completed_for_key[key]
            if seen == 0:
                # Nothing reported for this key — assume s5cmd had nothing
                # to do (already in sync / zero objects) and count it as
                # fully done.
                self.queue_done(key)
                done += expected_count
                self.queue_progress(done, total)
            elif seen < expected_count:
                # Partial completion with no error line seen: don't lie
                # about completeness. Surface it instead of silently
                # under-counting forever.
                self.queue_error(key, f"Expected {expected_count} files, only saw {seen}")

        return done


if __name__ == "__main__":
    app = App()
    app.mainloop()