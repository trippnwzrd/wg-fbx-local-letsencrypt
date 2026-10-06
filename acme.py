#!/usr/bin/env python3
"""Let's Encrypt Certificate Generation (locally-managed).

TUI wizard for locally-managed Firebox cert deploy over SSH.
Stdlib only. Never stores passwords.
Secrets: host/port/user via flags or FB_HOST/FB_PORT/FB_USER env. Password via getpass at runtime.
All generated plans go to output/ next to this script.
"""
import argparse
import getpass
import html
import os
import pty
import re
import secrets
import select
import shutil
import socket
import string
import struct
import subprocess
import sys
import threading
import time
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

BASE = Path(__file__).resolve().parent
OUT = BASE / "output"
OUT.mkdir(exist_ok=True)

DEFAULT_PORT = 4118
DEFAULT_HOST = "10.0.1.1"
DEFAULT_USER = "status"

GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
RESET = "\033[0m"


def green(s: str) -> str:
    return f"{GREEN}{s}{RESET}"


def yellow(s: str) -> str:
    return f"{YELLOW}{s}{RESET}"


def red(s: str) -> str:
    return f"{RED}{s}{RESET}"


def set_title(text: str):
    sys.stdout.write(f"\033]0;{text}\007")
    sys.stdout.flush()


# ---------------------------------------------------------------------------
# Fireware certificate parsing / classification
# ---------------------------------------------------------------------------

def _clean(s: str) -> str:
    """Unescape device HTML entities (e.g. Let&apos;s Encrypt) and strip."""
    return html.unescape(s or "").strip()


def parse_web_server_cert(text: str) -> dict:
    """Parse `show web-server-cert` output.

    Observed (LE in use):
      ---Third party certificate : 30001
    Self-signed/default is expected to look like e.g.:
      ---Self-signed certificate ... / ---Default ... / ---Fireware ...
    Returns {kind, cert_id, raw}.
    """
    t = _clean(text)
    m = re.search(r"third\s*party\s*certificate\s*:\s*(\d+)", t, re.I)
    if m:
        return {"kind": "third-party", "cert_id": m.group(1), "raw": text}
    m = re.search(r"self.signed[^\n:]*:?\s*(\d+)?", t, re.I)
    if m or re.search(r"self.signed|fireware|default", t, re.I):
        mid = re.search(r":\s*(\d+)", t)
        return {"kind": "self-signed", "cert_id": mid.group(1) if mid else "", "raw": text}
    mid = re.search(r"certificate\s*:\s*(\d+)", t, re.I)
    if mid:
        return {"kind": "unknown-id", "cert_id": mid.group(1), "raw": text}
    return {"kind": "unknown", "cert_id": "", "raw": text}


def parse_cert_detail(text: str) -> dict:
    """Parse `show certificate <id>` into a dict of lower-cased fields."""
    d: dict = {}
    for line in _clean(text).splitlines():
        if ":" not in line:
            continue
        k, _, v = line.partition(":")
        k = k.strip().lower()
        if k in ("certificate id", "type", "algorithm", "name", "key usage",
                 "key length", "subject", "issuer", "dns name", "ip address",
                 "user domain name", "valid from", "valid to", "fingerprint",
                 "subject alt", "extended usage"):
            d[k] = _clean(v)
    m = re.search(r"certificate\s*<(\d+)>", _clean(text), re.I)
    if m and "certificate id" not in d:
        d["certificate id"] = m.group(1)
    return d


def parse_fireware_date(s: str) -> datetime | None:
    """Parse Fireware dates like 'Sep 30 19:47:00 2026 GMT' -> aware UTC datetime."""
    s = (s or "").strip().replace("GMT", "+0000").replace("UTC", "+0000")
    for fmt in ("%b %d %H:%M:%S %Y %z", "%b %d %H:%M:%S %Y", "%Y-%m-%d %H:%M:%S %z"):
        try:
            dt = datetime.strptime(s, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            continue
    return None


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", (s or "").lower())


def is_self_signed_detail(d: dict) -> bool:
    """Heuristic: Fireware CA / self-signed detection."""
    issuer, subject = _norm(d.get("issuer", "")), _norm(d.get("subject", ""))
    blob = f"{issuer} {subject} {d.get('name', '')}".lower()
    if any(k in issuer for k in ("fireware", "watchguard", "firebox")):
        return True
    if subject and subject == issuer:
        return True
    if any(k in blob for k in ("fireware ca", "self-signed", "self signed", "default web")):
        return True
    return False


def is_letsencrypt_detail(d: dict) -> bool:
    blob = _norm(f"{d.get('issuer', '')} {d.get('name', '')}")
    return ("let's encrypt" in blob or "lets encrypt" in blob
            or "letsencrypt" in blob or "let&apos;s encrypt" in blob)


def classify_cert(web: dict, detail: dict, now: datetime | None = None) -> dict:
    """Return status dict: category, expired, days_left, summary."""
    now = now or datetime.now(timezone.utc)
    valid_to = parse_fireware_date(detail.get("valid to", ""))
    days_left = (valid_to - now).days if valid_to else None
    expired = valid_to is not None and valid_to <= now
    self_signed = is_self_signed_detail(detail)
    le = is_letsencrypt_detail(detail)
    cid = detail.get("certificate id", "") or web.get("cert_id", "")
    subj = detail.get("subject", "")
    if self_signed:
        cat = "self-signed"
    elif le and expired:
        cat = "letsencrypt-expired"
    elif le and days_left is not None and days_left <= 30:
        cat = "letsencrypt-expiring"
    elif le:
        cat = "letsencrypt-valid"
    elif expired:
        cat = "third-party-expired"
    elif web.get("kind") == "third-party":
        cat = "third-party-valid"
    else:
        cat = "unknown"
    if cat == "self-signed":
        summary = (f"Web server cert [{cid}] is SELF-SIGNED (Fireware CA/default). "
                   "Eligible for new Let's Encrypt issuance.")
    elif cat == "letsencrypt-valid":
        summary = (f"Let's Encrypt cert [{cid}] ({subj}) valid, "
                   f"expires {detail.get('valid to', '?')} ({days_left}d left). No action needed.")
    elif cat == "letsencrypt-expiring":
        summary = (f"Let's Encrypt cert [{cid}] expiring soon: "
                   f"{detail.get('valid to', '?')} ({days_left}d left). Renew recommended.")
    elif cat == "letsencrypt-expired":
        summary = (f"Let's Encrypt cert [{cid}] EXPIRED on {detail.get('valid to', '?')}. "
                   "Renewal required (same-subject re-import workaround applies).")
    elif cat == "third-party-expired":
        summary = f"Third-party cert [{cid}] EXPIRED on {detail.get('valid to', '?')}."
    elif cat == "third-party-valid":
        summary = f"Third-party cert [{cid}] in use, expires {detail.get('valid to', '?')}."
    else:
        summary = f"Could not classify cert [{cid}]. Check detail output manually."
    return {"category": cat, "cert_id": cid, "subject": subj,
            "issuer": detail.get("issuer", ""),
            "valid_from": detail.get("valid from", ""),
            "valid_to": detail.get("valid to", ""),
            "days_left": days_left, "expired": expired,
            "self_signed": self_signed, "is_letsencrypt": le,
            "summary": summary, "detail": detail, "web": web}


# ---------------------------------------------------------------------------
# Local openssl / certbot helpers (system binaries, stdlib only)
# ---------------------------------------------------------------------------

def need_bin(name: str) -> str | None:
    return shutil.which(name)


def gen_pfx_password(length: int = 32) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def gen_key_and_csr(domain: str, outdir: Path, key_bits: int = 2048) -> tuple[Path, Path]:
    """Create privkey.pem + <domain>.csr via openssl. Returns (key, csr)."""
    if not need_bin("openssl"):
        raise RuntimeError("openssl binary not found in PATH")
    outdir.mkdir(parents=True, exist_ok=True)
    key = outdir / "privkey.pem"
    csr = outdir / f"{domain}.csr"
    subprocess.run(["openssl", "genrsa", "-out", str(key), str(key_bits)],
                   check=True, capture_output=True, text=True, timeout=60)
    try:
        key.chmod(0o600)
    except OSError:
        pass
    subprocess.run(["openssl", "req", "-new", "-key", str(key), "-out", str(csr),
                    "-subj", f"/CN={domain}",
                    "-addext", f"subjectAltName=DNS:{domain}"],
                   check=True, capture_output=True, text=True, timeout=30)
    return key, csr


def make_pfx(fullchain: Path, privkey: Path, out_pfx: Path, password: str) -> Path:
    """Bundle cert+key into .pfx (PKCS#12) for Firebox import."""
    if not need_bin("openssl"):
        raise RuntimeError("openssl binary not found in PATH")
    if not fullchain.is_file() or not privkey.is_file():
        raise FileNotFoundError(f"missing input: {fullchain} / {privkey}")
    out_pfx.parent.mkdir(parents=True, exist_ok=True)
    # Try cert+chain split first (cert.pem + chain.pem layout), fall back to fullchain as -in.
    cert_pem = fullchain.parent / "cert.pem"
    chain_pem = fullchain.parent / "chain.pem"
    if cert_pem.is_file() and chain_pem.is_file():
        cmd = ["openssl", "pkcs12", "-export", "-out", str(out_pfx),
               "-inkey", str(privkey), "-in", str(cert_pem),
               "-certfile", str(chain_pem), "-passout", f"pass:{password}"]
    else:
        cmd = ["openssl", "pkcs12", "-export", "-out", str(out_pfx),
               "-inkey", str(privkey), "-in", str(fullchain),
               "-passout", f"pass:{password}"]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    if r.returncode != 0:
        raise RuntimeError(f"openssl pkcs12 failed: {r.stderr.strip() or r.stdout.strip()}")
    return out_pfx


def _pfx_matches(pfx: Path, password: str, cert: Path) -> bool:
    """True if the .pfx already bundles exactly `cert` (same leaf fingerprint)."""
    try:
        leaf = subprocess.run(["openssl", "pkcs12", "-in", str(pfx), "-clcerts",
                               "-nokeys", "-passin", f"pass:{password}"],
                              capture_output=True, timeout=30)
        fp1 = subprocess.run(["openssl", "x509", "-noout", "-fingerprint", "-sha256"],
                             input=leaf.stdout, capture_output=True, timeout=30)
        fp2 = subprocess.run(["openssl", "x509", "-noout", "-fingerprint", "-sha256",
                              "-in", str(cert)],
                             capture_output=True, timeout=30)
        return (fp1.returncode == fp2.returncode == 0
                and bool(fp1.stdout.strip())
                and fp1.stdout.strip() == fp2.stdout.strip())
    except Exception:
        return False


def certbot_obtain(domain: str, email: str, staging: bool = False,
                   webroot: str | None = None, dry_run: bool = False) -> tuple[list, Path | None]:
    """Build (and optionally run) certbot HTTP-01 issuance.

    Returns (cmd, live_dir_or_None). Port 80 must reach THIS host for
    --standalone; use --webroot when a web server already serves port 80.
    """
    cb = need_bin("certbot")
    if not cb:
        raise RuntimeError("certbot not found. Install: sudo apt install certbot  (or snap). "
                           "Cannot proceed with HTTP-01 without it.")
    cmd = [cb, "certonly", "--non-interactive", "--agree-tos", "-m", email,
           "--preferred-challenges", "http-01"]
    if staging:
        cmd += ["--staging"]
    if webroot:
        cmd += ["--webroot", "-w", webroot]
    else:
        cmd += ["--standalone"]
    cmd += ["-d", domain]
    live = Path(f"/etc/letsencrypt/live/{domain}")
    if dry_run:
        return cmd, None
    if _live_is_staging(domain) is not None and _live_is_staging(domain) != staging:
        # Switching profiles (staging<->production) on an existing lineage:
        # otherwise certbot reports success without replacing anything.
        cmd += ["--force-renewal"]
        print("  (switching staging<->production: forcing renewal)")
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    if r.returncode != 0:
        raise RuntimeError(f"certbot failed:\n{r.stdout}\n{r.stderr}")
    fullchain = live / "fullchain.pem"
    privkey = live / "privkey.pem"
    if not fullchain.is_file():
        # staging / alternate layout: best effort — point user at live dir
        return cmd, live if live.is_dir() else None
    return cmd, live


def _live_is_staging(domain: str) -> bool | None:
    """Inspect the existing lineage cert: True if staging-issued,
    False if production, None if no lineage / unreadable."""
    cert = Path(f"/etc/letsencrypt/live/{domain}/cert.pem")
    if not cert.is_file():
        return None
    try:
        r = subprocess.run(["openssl", "x509", "-noout", "-issuer", "-in", str(cert)],
                           capture_output=True, text=True, timeout=10)
        if r.returncode != 0:
            return None
        return "staging" in r.stdout.lower()
    except Exception:
        return None


def certbot_renew(domain: str, staging: bool = False) -> list:
    """Force-renew a single lineage. Returns the command used."""
    cb = need_bin("certbot")
    if not cb:
        raise RuntimeError("certbot not found.")
    cmd = [cb, "certonly", "--non-interactive", "--agree-tos", "--force-renewal",
           "--preferred-challenges", "http-01", "--standalone", "-d", domain]
    if staging:
        cmd += ["--staging"]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    if r.returncode != 0:
        raise RuntimeError(f"certbot renew failed:\n{r.stdout}\n{r.stderr}")
    return cmd


class FireboxSession:
    """Persistent PTY SSH session: connect once, run many commands.

    Uses pty.fork so OpenSSH gets a controlling TTY (single password prompt).
    Password is kept in memory only for connect, then cleared.
    """

    def __init__(self, host: str, port: int, user: str, password: str, timeout: float = 30.0):
        self.host, self.port, self.user = host, port, user
        self.timeout = timeout
        self.pid, self.fd = pty.fork()
        if self.pid == 0:
            os.execvp("ssh", ["ssh", "-p", str(port), "-tt",
                              "-o", "StrictHostKeyChecking=accept-new",
                              f"{user}@{host}"])
        self.banner = ""
        self.prompt = ""
        self.connected = False
        self._connect(password)
        password = ""

    def _read_until(self, markers: tuple, timeout: float) -> str:
        buf = bytearray()
        deadline = time.time() + timeout
        while time.time() < deadline:
            r, _, _ = select.select([self.fd], [], [], 1.0)
            if not r:
                continue
            try:
                chunk = os.read(self.fd, 65536)
            except OSError:
                break
            if not chunk:
                break
            buf += chunk
            low = bytes(buf[-16384:]).lower()
            for m in markers:
                if m in low:
                    return bytes(buf).decode(errors="replace")
            if b"--more--" in low or b"-- more --" in low:
                os.write(self.fd, b" ")
        return bytes(buf).decode(errors="replace")

    def _connect(self, password: str):
        pw_bytes = password.encode()
        sent_pw = False
        buf = bytearray()
        deadline = time.time() + self.timeout
        while time.time() < deadline:
            r, _, _ = select.select([self.fd], [], [], 1.0)
            if not r:
                continue
            try:
                chunk = os.read(self.fd, 65536)
            except OSError:
                break
            if not chunk:
                break
            buf += chunk
            low = bytes(buf[-16384:]).lower()
            if b"are you sure you want to continue connecting" in low:
                os.write(self.fd, b"yes\n")
                buf.clear()
                continue
            if not sent_pw and b"password:" in low:
                os.write(self.fd, pw_bytes + b"\n")
                sent_pw = True
                pw_bytes = b""
                buf.clear()
                continue
            if b"wg>" in low or b"wg#" in low:
                self.banner = bytes(buf).decode(errors="replace")
                self.prompt = "WG#" if b"wg#" in low else "WG>"
                self.connected = True
                pw_bytes = b""
                return
        pw_bytes = b""
        raise TimeoutError("did not reach WG>/WG# prompt (wrong password or host)")

    def run(self, cmd: str, timeout: float = 30.0, submit: bool = True) -> str:
        """Send one command after prompt, collect until next prompt. Handles pager.

        submit=False sends the text without Enter (for '?' help hotkey,
        where Enter would execute the line as a real command).
        """
        os.write(self.fd, cmd.encode() + (b"\n" if submit else b""))
        out = bytearray()
        deadline = time.time() + timeout
        # skip echo of our own command: wait a bit then collect
        time.sleep(0.3)
        while time.time() < deadline:
            r, _, _ = select.select([self.fd], [], [], 1.0)
            if not r:
                continue
            try:
                chunk = os.read(self.fd, 65536)
            except OSError:
                break
            if not chunk:
                break
            out += chunk
            low = bytes(out[-16384:]).lower()
            if b"--more--" in low or b"-- more --" in low:
                os.write(self.fd, b" ")
                continue
            # next device prompt means command finished (ignore the echoed cmd line)
            # (config)# is the configure-mode prompt, needed for web-server-cert select
            if b"wg>" in low or b"wg#" in low or b"(config)#" in low:
                # ensure we got more than just the echo
                if len(out) > len(cmd) + 10:
                    break
        if not submit:
            # clear the pending input line left behind by the '?' hotkey
            try:
                os.write(self.fd, b"\x03")
                time.sleep(0.3)
                while True:
                    r, _, _ = select.select([self.fd], [], [], 0.5)
                    if not r:
                        break
                    chunk = os.read(self.fd, 65536)
                    if not chunk:
                        break
                    out += chunk
                    low = bytes(out[-16384:]).lower()
                    if b"wg>" in low or b"wg#" in low or b"(config)#" in low:
                        break
            except OSError:
                pass
        text = out.decode(errors="replace")
        return text

    def close(self):
        try:
            os.write(self.fd, b"exit\n")
            time.sleep(0.5)
        except OSError:
            pass
        try:
            os.close(self.fd)
        except OSError:
            pass
        try:
            os.waitpid(self.pid, 0)
        except (ChildProcessError, OSError):
            pass


def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")


def tui_wizard(args) -> argparse.Namespace:
    clear_screen()
    print()
    _t = "Let's Encrypt Certificate Generation (locally-managed)"
    _w = max(36, len(_t) + 2)
    print("┌" + "─" * _w + "┐")
    print("│" + _t.center(_w) + "│")
    print("└" + "─" * _w + "┘")
    print()
    host = input(f"Firebox host [{args.host or DEFAULT_HOST}]: ").strip() or (args.host or DEFAULT_HOST)
    port_s = input(f"SSH port [{args.port}]: ").strip() or str(args.port)
    user = input(f"Username [{args.user}]: ").strip() or args.user
    password = getpass.getpass(f"Password for {user} (not stored): ")
    args.host, args.port, args.user = host, int(port_s), user
    args.password = password
    return args


def _session_dead(text: str) -> bool:
    """True if device output shows the SSH session timed out / closed."""
    low = (text or "").lower()
    if not low.strip():
        return True
    return ("command line timeout" in low
            or ("connection to" in low and "closed" in low))


def _run_or_dead(sess: FireboxSession, cmd: str, timeout: float = 20.0) -> str | None:
    """Run a command; on dead session print one clean line and return None."""
    try:
        out = sess.run(cmd, timeout=timeout)
    except (OSError, EOFError):
        print(red("Session closed by the Firebox."))
        print()
        return None
    if _session_dead(out):
        print(red("Session closed by the Firebox (command line timeout)."))
        print()
        return None
    return out


def assess_firebox(sess: FireboxSession) -> dict:
    """Auto-detect web-server-cert state: self-signed vs LE valid/expiring/expired.

    Runs `show web-server-cert` then `show certificate <id>`, parses and
    classifies. Prints a human summary.
    Raises ConnectionError if the session died; returns category 'unknown'
    (never raises) on parse failure.
    """
    web_raw = _run_or_dead(sess, "show web-server-cert", timeout=20.0)
    if web_raw is None:
        raise ConnectionError("session closed")
    web = parse_web_server_cert(web_raw)
    detail: dict = {}
    detail_raw = ""
    if web.get("cert_id"):
        detail_raw = _run_or_dead(sess, f"show certificate {web['cert_id']}", timeout=20.0)
        if detail_raw is None:
            raise ConnectionError("session closed")
        detail = parse_cert_detail(detail_raw)
    else:
        # No numeric ID (e.g. "Default Certificate signed by Firebox"):
        # don't dump raw device text; classify from what we have.
        if web.get("kind") == "self-signed":
            status = {"category": "self-signed", "cert_id": "",
                      "subject": "", "issuer": "Default Certificate signed by Firebox",
                      "valid_from": "", "valid_to": "", "days_left": None, "expired": False,
                      "self_signed": True, "is_letsencrypt": False,
                      "summary": ("Web server uses the DEFAULT Firebox-signed "
                                  "(self-signed) certificate. "
                                  "Eligible for new Let's Encrypt issuance."),
                      "detail": {}, "web": web}
        else:
            status = {"category": "unknown", "cert_id": "",
                      "subject": "", "issuer": "", "valid_from": "", "valid_to": "",
                      "days_left": None, "expired": False,
                      "self_signed": False, "is_letsencrypt": False,
                      "summary": ("Could not determine the web server certificate. "
                                  "Use 1) Show certificates to inspect manually."),
                      "detail": {}, "web": web}
        print(color_for_category(status["category"], "Status: " + status["summary"]))
        print()
        return status
    status = classify_cert(web, detail)
    status["web_raw"] = web_raw
    status["detail_raw"] = detail_raw
    # coloured one-line banner (same coding as install_menu's Status: line)
    cat = status["category"]
    print(color_for_category(cat, "Status: " + status["summary"]))
    print()
    for label, value in (
            ("Subject", status.get("subject", "?")),
            ("Issuer", status.get("issuer", "?")),
            ("Valid from", status.get("valid_from", "?") or "?"),
            ("Valid to", status.get("valid_to", "?"))):
        print(f"  {label}: {value}")
    print()
    return status


def color_for_category(cat: str, text: str) -> str:
    """Consistent colour coding: green=valid, yellow=self-signed/expiring, red=expired."""
    if cat in ("letsencrypt-valid", "third-party-valid"):
        return green(text)
    if cat in ("letsencrypt-expired", "third-party-expired"):
        return red(text)
    if cat in ("self-signed", "letsencrypt-expiring"):
        return yellow(text)
    return text


def _short(path: Path) -> str:
    """Short display path relative to the tool dir (avoids long absolute lines)."""
    try:
        return str(path.relative_to(BASE))
    except (ValueError, AttributeError):
        return str(path)


def _hand_back(path: Path) -> None:
    """When running under sudo, give new artifacts back to the invoking user
    so they stay usable (file manager, browser upload) instead of root-only."""
    sudo_user = os.environ.get("SUDO_USER")
    if not sudo_user or os.geteuid() != 0:
        return
    try:
        import pwd as _pwd
        pw = _pwd.getpwnam(sudo_user)
        os.chown(path, pw.pw_uid, pw.pw_gid)
    except (KeyError, OSError):
        pass


def _prompt_domain(default: str) -> str:
    while True:
        suffix = f" [{default}]" if default else ""
        d = input(f"Domain for Let's Encrypt{suffix}: ").strip() or default
        if d:
            return d
        print("Domain is required.")


def _prompt_email() -> str:
    while True:
        e = input("Contact email for Let's Encrypt (expiry notices): ").strip()
        if re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", e):
            return e
        print("Please enter a valid email address.")


def _local_ip_for(host: str) -> str | None:
    """LAN source IP this host would use toward `host` (no traffic sent)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((host, 4118))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except OSError:
        return None


class TFTPServer:
    """Minimal read-only TFTP server (RFC 1350, octet, 512B blocks).

    Stdlib only. Serves ONLY the allowlisted basenames from `root`
    (path traversal impossible: basename match + root join). Stops on demand.
    """

    def __init__(self, root: Path, allow: tuple = (), port: int = 69):
        self.root = root
        self.allow = set(allow)
        self.port = port
        self.done = threading.Event()
        self.served_file: str | None = None
        self.requests: list = []  # (addr, filename) per RRQ, for diagnostics
        self.client_ip: str | None = None  # when set, RRQs from others are ignored
        self.error: str | None = None
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> bool:
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind(("0.0.0.0", self.port))
        except OSError as e:
            self.error = str(e)
            return False
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()
        return True

    def stop(self) -> None:
        self._stop.set()
        try:
            self.sock.close()
        except (OSError, AttributeError):
            pass
        if self._thread is not None:
            self._thread.join(timeout=3)

    def allow_add(self, name: str) -> None:
        """Add one more basename to the allowlist (e.g. an auto-fetched root)."""
        self.allow.add(name)

    def _send_error(self, addr, code: int, msg: str) -> None:
        try:
            self.sock.sendto(struct.pack("!HH", 5, code) + msg.encode() + b"\x00", addr)
        except OSError:
            pass

    def _serve(self) -> None:
        self.sock.settimeout(1.0)
        while not self._stop.is_set():
            try:
                data, addr = self.sock.recvfrom(1024)
            except socket.timeout:
                continue
            except OSError:
                break
            if len(data) < 4 or struct.unpack("!H", data[:2])[0] != 1:  # RRQ only
                continue
            if self.client_ip is not None and addr[0] != self.client_ip:
                continue  # IP-locked (e.g. while serving key material): ignore others
            parts = data[2:].split(b"\x00")
            if len(parts) < 2:
                continue
            name = parts[0].decode("utf-8", "replace").rsplit("/", 1)[-1]
            self.requests.append((addr, name))
            if name not in self.allow:
                self._send_error(addr, 1, "File not found")
                continue
            target = self.root / name
            if not target.is_file():
                self._send_error(addr, 1, "File not found")
                continue
            self._send_file(target, addr)

    def _send_file(self, path: Path, client) -> None:
        try:
            blob = path.read_bytes()
        except OSError:
            return
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(5.0)
        try:
            s.bind(("0.0.0.0", 0))
            block, offset = 1, 0
            while not self._stop.is_set():
                chunk = blob[offset:offset + 512]
                pkt = struct.pack("!HH", 3, block & 0xFFFF) + chunk
                for _ in range(6):
                    try:
                        s.sendto(pkt, client)
                        ack, src = s.recvfrom(516)
                    except socket.timeout:
                        continue
                    if src != client or len(ack) < 4:
                        continue
                    op, num = struct.unpack("!HH", ack[:4])
                    if op == 5:  # client ERROR
                        return
                    if op == 4 and num == (block & 0xFFFF):
                        break
                else:
                    return  # retries exhausted
                if len(chunk) < 512:  # final block ACKed
                    self.served_file = path.name
                    self.done.set()
                    return
                offset += 512
                block += 1
        finally:
            s.close()


KNOWN_ROOTS = {
    "isrg root x1": "https://letsencrypt.org/certs/isrgrootx1.pem",
    "isrg root x2": "https://letsencrypt.org/certs/isrg-root-x2.pem",
}

ROOT_DOC_PAGES = (
    "https://letsencrypt.org/docs/staging-environment/",
    "https://letsencrypt.org/certs/",
)


def _find_root_url(cn: str) -> str | None:
    """Map a root CN to a PEM download: known table first, then anchor on the
    CN's section of Let's Encrypt's staging/certs pages (name, closely
    followed by `(self-signed)`, closely followed by its .pem link)."""
    key = cn.strip().lower()
    if key in KNOWN_ROOTS:
        return KNOWN_ROOTS[key]
    tokens = [w for w in re.findall(r"[a-z]+", key)
              if w not in ("staging", "root", "ca") and len(w) >= 3]
    if not tokens:
        return None
    best = None  # ((gap, cross_signed), url)
    for page in ROOT_DOC_PAGES:
        try:
            with urllib.request.urlopen(page, timeout=30) as r:
                html = r.read(500000).decode("utf-8", "replace")
        except Exception:
            continue
        low = html.lower()
        for s in re.finditer(r"\(self-signed\)", low):
            back = low[max(0, s.start() - 300):s.start()]
            ends = []
            for t in tokens:
                p = back.rfind(t)
                if p == -1:
                    break
                ends.append(p + len(t))
            else:
                gap = len(back) - max(ends)
                fwd = html[s.end():s.end() + 400]
                pm = re.search(r'href="([^"]+\.pem)"', fwd, re.I)
                if pm:
                    score = (gap, "-by-" in pm.group(1).lower())
                    if best is None or score < best[0]:
                        best = (score, urllib.parse.urljoin(page, pm.group(1)))
    return best[1] if best else None


def _store_pem(destdir: Path, src: str) -> str | None:
    """Download (http/https) or copy (path) a PEM into destdir/root.pem.
    Returns the basename, or None on failure."""
    dest = destdir / "root.pem"
    try:
        if src.startswith(("http://", "https://")):
            with urllib.request.urlopen(src, timeout=30) as r:
                blob = r.read(102400)
            if len(blob) >= 102400 or b"BEGIN CERTIFICATE" not in blob:
                print(red("  Download is not a PEM certificate."))
                return None
            dest.write_bytes(blob)
        else:
            p = Path(src).expanduser()
            if not p.is_file() or "BEGIN CERTIFICATE" not in p.read_text(errors="replace"):
                print(red("  Not a PEM certificate file."))
                return None
            shutil.copy2(p, dest)
        _hand_back(dest)
        print(green(f"  staged: {_short(dest)}"))
        return dest.name
    except Exception as e:
        print(red(f"  Fetch failed: {e}"))
        return None


def _stage_root(workdir: Path) -> str | None:
    """Resolve a Firebox-demanded root CA and stage it as root.pem.

    Paste the box's %Error (auto-extracts the DN and resolves the download),
    or give a PEM path/URL directly. Empty skips.
    """
    src = input("  Root CA — paste %Error, PEM path/URL, or empty to skip: ").strip()
    if not src:
        return None
    cn = None
    m = re.search(r"<([^<>]*?cn\s*=\s*[^<>]+)>", src, re.I)
    if m and "error" in src.lower():
        parts = re.split(r"cn\s*=", m.group(1), flags=re.I)
        if len(parts) == 2 and parts[1].strip():
            cn = parts[1].strip()
    if cn:
        print(f"  Box needs root: {cn}")
        url = _find_root_url(cn)
        if url:
            print(f"  Resolved: {url}")
            return _store_pem(workdir, url)
        print(yellow("  No known download for that root — paste its PEM path/URL:"))
        src = input("  PEM path/URL, empty to skip: ").strip()
        if not src:
            return None
    return _store_pem(workdir, src)


def _fetch_pem(destdir: Path, what: str) -> str | None:
    """Legacy manual prompt kept for compatibility; prefers _stage_root."""
    src = input(f"  {what} — file path or http(s) URL, empty to skip: ").strip()
    if not src:
        return None
    return _store_pem(destdir, src)


def _wait_for_fetch(tftp: TFTPServer, name: str, timeout: float = 300) -> bool:
    """Wait until `name` is fully fetched; narrate incoming RRQs while waiting."""
    tftp.done.clear()
    seen = len(tftp.requests)
    deadline = time.time() + timeout
    try:
        while time.time() < deadline:
            if tftp.done.wait(timeout=10) and tftp.served_file == name:
                return True
            tftp.done.clear()
            while len(tftp.requests) > seen:
                addr, rname = tftp.requests[seen]
                seen += 1
                print(f"  ... request from {addr[0]} for {rname}")
    except KeyboardInterrupt:
        print()
    return False


def _drain_stdin() -> None:
    """Discard stray keystrokes typed while the TUI was blocked (e.g. during
    the TFTP wait) so they can't misanswer the next confirmation prompt."""
    try:
        if not sys.stdin.isatty():
            return
        while select.select([sys.stdin], [], [], 0)[0]:
            data = os.read(sys.stdin.fileno(), 65536)
            if not data:
                break
    except (OSError, ValueError):
        pass


def _manual_pem_loop(sess: FireboxSession, tftp: TFTPServer | None,
                     lip: str | None, pems: list) -> bool:
    """Manual-paste variant (read-only session): prints each command, waits
    for the fetch, asks confirmation. Returns True when all are confirmed."""
    for fname, label in pems:
        url = f"tftp://{lip}/{fname}" if tftp is not None else f"tftp://<server>/{fname}"
        print(f"  Admin session, paste ({label}):")
        print(f"    import certificate general-usage from {url}")
        if tftp is not None:
            print("  Waiting for fetch (5 min max, Ctrl+C skips) ...")
            print(green(f"  {fname} fetched.") if _wait_for_fetch(tftp, fname)
                  else yellow(f"  {fname} not fetched."))
        _drain_stdin()
        if input(f"  Imported {fname}? [y/N]: ").strip().lower() not in ("y", "yes"):
            print("  Paused. Re-run option 2 to resume.")
            if tftp is not None:
                tftp.stop()
            return False
    if tftp is not None:
        tftp.stop()
        print("  TFTP stopped.")
    return True


def _firebox_ip(sess: FireboxSession) -> str | None:
    """Resolve the Firebox address to an IP (for TFTP source-locking)."""
    try:
        return socket.gethostbyname(sess.host)
    except OSError:
        return None


def _try_key_bundle(sess: FireboxSession, tftp: TFTPServer, lip: str,
                    workdir: Path, live: Path, domain: str) -> bool:
    """Try a combined-PEM import (cert+key+chain) so the box gets the private
    key over CLI. IP-locks TFTP to the Firebox, deletes the bundle after.
    Returns True if the box accepted it."""
    try:
        cert = (workdir / "cert.pem").read_text()
        key = (live / "privkey.pem").read_text()
        chain = (workdir / "chain.pem").read_text()
    except OSError as e:
        print(red(f"  Bundle build failed: {e}"))
        return False
    if "PRIVATE KEY" not in key or "CERTIFICATE" not in cert:
        print(red("  Unexpected file contents — skipping bundle attempt."))
        return False
    fip = _firebox_ip(sess)
    if not fip:
        print(red("  Cannot resolve Firebox IP — refusing to serve the key openly."))
        return False
    tftp.client_ip = fip
    bundle = workdir / f"{domain}-bundle.pem"
    try:
        for order, parts in (("cert+key+chain", (cert, key, chain)),
                             ("key+cert+chain", (key, cert, chain))):
            bundle.write_text("".join(p if p.endswith("\n") else p + "\n" for p in parts))
            try:
                bundle.chmod(0o600)
            except OSError:
                pass
            _hand_back(bundle)
            tftp.allow_add(bundle.name)
            tftp.done.clear()
            cmd = f"import certificate general-usage from tftp://{lip}/{bundle.name}"
            try:
                out = sess.run(cmd, timeout=180.0)
            except (OSError, EOFError):
                print(red("  Session closed."))
                break
            low = out.lower()
            fetched = tftp.done.is_set() and tftp.served_file == bundle.name
            if "%error" not in low and "error:" not in low and not _session_dead(out) and fetched:
                print(green("  Bundle (cert + key): imported."))
                return True
            print(yellow(f"  Bundle ({order}): rejected:"))
            print("\n".join(out.strip().splitlines()[-4:]))
    finally:
        tftp.client_ip = None
        try:
            bundle.unlink()
        except OSError:
            pass
    return False


def _auto_pem_loop(sess: FireboxSession, tftp: TFTPServer, lip: str,
                   pems: list, workdir: Path, live: Path, domain: str):
    """Admin-session variant: sends each import directly and parses the
    result. A demanded root CA is auto-resolved, staged, queued first and
    retried; a demanded private key triggers a combined-bundle attempt.
    Returns True when all imported, "bundle" when the key attached via
    bundle (no .pfx needed), "partial" when only the key step remains
    (finish via .pfx), False to abort."""
    queue = list(pems)
    seen_roots: set = set()
    while queue:
        fname, _label = queue[0]
        cmd = f"import certificate general-usage from tftp://{lip}/{fname}"
        try:
            out = sess.run(cmd, timeout=180.0)
        except (OSError, EOFError):
            print(red("  Session closed."))
            tftp.stop()
            return False
        low = out.lower()
        if "password:" in low and "%error" not in low:
            try:
                os.write(sess.fd, b"\x03")
                time.sleep(0.5)
            except OSError:
                pass
            print(red("  Device asked for interactive input — aborted. Finish manually."))
            tftp.stop()
            return False
        if any(k in low for k in ("permission denied", "access denied",
                                  "not allowed", "privilege")):
            print(red("  Box refused the command — finish manually:"))
            print(f"    {cmd}")
            tftp.stop()
            return False
        m = re.search(r"must import the certificate for\s*<([^<>]+)>", out, re.I)
        if m and "%error" in low:
            parts = re.split(r"cn\s*=", m.group(1), flags=re.I)
            cn = parts[1].strip() if len(parts) == 2 and parts[1].strip() else m.group(1).strip()
            if cn.lower() in seen_roots:
                print(red(f"  Root {cn} already attempted — stopping for manual check."))
                tftp.stop()
                return False
            seen_roots.add(cn.lower())
            rurl = _find_root_url(cn)
            if rurl:
                print(yellow(f"  Root required ({cn}) → {rurl}"))
            if rurl and _store_pem(workdir, rurl):
                tftp.allow_add("root.pem")
                queue.insert(0, ("root.pem", "root CA (first)"))
                continue
            print(red("  Could not fetch that root — import it manually, then re-run."))
            tftp.stop()
            return False
        if "private key does not match" in low:
            print(yellow(f"  {fname}: private key required — trying combined bundle..."))
            if _try_key_bundle(sess, tftp, lip, workdir, live, domain):
                tftp.stop()
                return "bundle"
            print(yellow("  Bundle rejected — chain/root imports above stand; finish via Web UI/WSM .pfx."))
            tftp.stop()
            print("  TFTP stopped.")
            return "partial"
        if "edit mode" in low:
            holder = re.search(r"Administrator \S+ from (\S+)", out, re.I)
            who = f" ({holder.group(1)})" if holder else ""
            print(yellow(f"  Another admin{who} holds Edit Mode — only one editor at a time."))
            print("  In that session type `exit` (back to View Mode) or disconnect, then re-run.")
            tftp.stop()
            return False
        if "already exists" in low:
            print(green(f"  {fname}: already on-box."))
            queue.pop(0)
            continue
        if "%error" in low or "error:" in low:
            print(red("  Import failed:"))
            print("\n".join(out.strip().splitlines()[-6:]))
            tftp.stop()
            return False
        if _session_dead(out):
            print(red("  Session closed."))
            tftp.stop()
            return False
        print(green(f"  {fname}: imported."))
        queue.pop(0)
    tftp.stop()
    return True


def _config_enter(sess: FireboxSession):
    """Enter configure mode. Returns the output, or None (dead session / edit lock)."""
    out = _run_or_dead(sess, "configure", timeout=20.0)
    if out is None:
        return None
    if "(config)#" in out.lower():
        return out
    if "edit mode" in out.lower():
        print(yellow("  Another admin holds Edit Mode — release it and re-run."))
        return None
    print(red("  Could not enter config mode:"))
    print("\n".join(out.strip().splitlines()[-4:]))
    return None


def _config_exit(sess: FireboxSession) -> bool:
    """Leave configure mode. Returns True when back at the main prompt."""
    out = _run_or_dead(sess, "exit", timeout=20.0)
    if out is None:
        return False
    if "(config)#" in out.lower():
        print(red("  Still in config mode — type `exit` manually in the admin session."))
        return False
    return True


def _find_cert_id(output: str, domain: str) -> str:
    """Find the certificate ID for `domain`, handling both output shapes:
    the `show certificate` table (`30002 ... cn=...`) and the
    `-- Certificate <id> --` detail blocks."""
    dom = domain.lower()
    for line in output.splitlines():
        m = re.match(r"\s*(\d{5})\s+", line)
        if m and dom in line.lower():
            return m.group(1)
    blocks = re.split(r"(?=--\s*Certificate\s*<\d+>\s*--)", output, flags=re.I)
    for b in blocks:
        if dom in b.lower():
            m = re.search(r"certificate id\s*:\s*(\d+)", b.lower())
            if m:
                return m.group(1)
    return ""


def _auto_select(sess: FireboxSession, domain: str) -> bool:
    """Select the imported cert as web server cert via config mode.
    Probes `web-server-cert ?` (safe help text) to confirm the third-party
    syntax, previews the exact command, sends it after confirmation.
    Returns True to proceed to verification."""
    out = _run_or_dead(sess, "show certificate", timeout=60.0)
    if out is None:
        return False
    cid = _find_cert_id(out, domain)
    if not cid:
        print(yellow(f"  {domain} not listed yet — finish the import first, then re-run."))
        return False
    print(f"  Imported cert ID: {cid}")
    if _config_enter(sess) is None:
        return False
    # Space-? with Enter prints help without changing anything (observed pattern).
    help_out = _run_or_dead(sess, "web-server-cert ?", timeout=20.0)
    if help_out is None:
        return False
    if "third" not in help_out.lower().replace("-", " ").replace("_", " "):
        print(yellow("  `web-server-cert` offers no third-party option on this version:"))
        print(help_out)
        _config_exit(sess)
        print("  Select manually (Web UI), then re-run option 2 to verify.")
        return False
    cmd = f"web-server-cert third-party {cid}"
    print(f"  Will send (config mode): {cmd}")
    _drain_stdin()
    if input("  Select it now? [y/N]: ").strip().lower() not in ("y", "yes"):
        _config_exit(sess)
        print("  Paused. Re-run option 2 after selecting it.")
        return False
    try:
        res = sess.run(cmd, timeout=60.0)
    except (OSError, EOFError):
        print(red("  Session closed."))
        return False
    low = res.lower()
    if "%error" in low or "error:" in low or "invalid" in low:
        print(red("  Select failed:"))
        print("\n".join(res.strip().splitlines()[-6:]))
        _config_exit(sess)
        return False
    print(green("  Select command accepted."))
    return _config_exit(sess)


def issuance_flow(sess: FireboxSession, status: dict) -> None:
    """New-cert path (self-signed -> LE): CSR -> certbot HTTP-01 -> PFX -> CLI import -> select."""
    print()
    print("--- New Let's Encrypt certificate ---")
    default_domain = ""
    subj = status.get("subject", "") or ""
    m = re.search(r"cn\s*=\s*([A-Za-z0-9._*-]+)", subj, re.I)
    if m:
        default_domain = m.group(1)
    dns = (status.get("detail", {}) or {}).get("dns name", "")
    if dns:
        default_domain = default_domain or dns.split()[0]
    domain = _prompt_domain(default_domain)
    email = _prompt_email()
    staging_in = input("Use STAGING first (recommended)? [y/N]: ").strip().lower()
    staging = staging_in in ("y", "yes")
    webroot = input("Webroot path (empty = --standalone, needs port 80 free): ").strip() or None
    if not need_bin("certbot"):
        print(red("certbot binary not found."))
        print("Install then re-run this step, e.g.: sudo apt install certbot")
        print("Manual preview (nothing executed):")
        print(f"  sudo certbot certonly --standalone -m {email} "
              f"-d {domain} --preferred-challenges http-01"
              + (" --staging" if staging else ""))
        print("Port 80/TCP must reach this host from the internet (NAT + Firebox policy).")
        return
    if not need_bin("openssl"):
        print(red("openssl binary not found — cannot build CSR/PFX."))
        return
    workdir = OUT / "certs" / domain
    print(f"\n[1/6] Key + CSR ...")
    try:
        key_path, csr_path = gen_key_and_csr(domain, workdir)
        _hand_back(key_path)
        _hand_back(csr_path)
        print(green(f"  key: {_short(key_path)}"))
        print(green(f"  csr: {_short(csr_path)}"))
    except Exception as e:
        print(red(f"  key/CSR generation failed: {e}"))
        return
    print("\n[2/6] certbot HTTP-01 challenge "
          f"({'staging' if staging else 'PRODUCTION'}).")
    if webroot is None:
        print("  --standalone binds port 80 here: stop nginx/apache, allow Firebox TCP/80 NAT.")
    go = input("Run certbot now? [y/N]: ").strip().lower()
    if go not in ("y", "yes"):
        print("Skipped. Re-run step 2 when port 80 is ready:")
        print(f"  sudo certbot certonly --non-interactive --agree-tos -m {email} "
              f"--preferred-challenges http-01 "
              f"{'--webroot -w ' + webroot if webroot else '--standalone'} -d {domain}"
              + (" --staging" if staging else ""))
        print(f"  CSR kept at: {_short(csr_path)}")
        return
    try:
        cmd, live = certbot_obtain(domain, email, staging=staging,
                                   webroot=webroot, dry_run=False)
        print(green("  certbot succeeded."))
    except Exception as e:
        print(red(f"  {e}"))
        return
    if live is None:
        print(red("  certbot ran but live dir not found — check /etc/letsencrypt/live/."))
        return
    fullchain = live / "fullchain.pem"
    privkey = live / "privkey.pem"
    print("\n[3/6] Bundling .pfx ...")
    pfx = workdir / f"{domain}.pfx"
    pwd_file = workdir / f"{domain}.pfx.password.txt"
    pfx_fresh = False
    reuse = False
    if pfx.is_file() and pwd_file.is_file():
        try:
            saved = pwd_file.read_text().splitlines()[0].strip()
        except (OSError, IndexError):
            saved = ""
        if saved and _pfx_matches(pfx, saved, live / "cert.pem"):
            reuse = True
            print(green(f"  unchanged — reusing {_short(pfx)}"))
            print(green(f"  password file: {_short(pwd_file)}"))
    if not reuse:
        pfx_fresh = True
        password = gen_pfx_password(32)
        try:
            make_pfx(fullchain, privkey, pfx, password)
            pwd_file.write_text(password + "\n")
            try:
                pwd_file.chmod(0o600)
            except OSError:
                pass
            _hand_back(pfx)
            _hand_back(pwd_file)
            print(green(f"  pfx: {_short(pfx)}"))
            print(green(f"  password file: {_short(pwd_file)}"))
            print(yellow(f"  PFX password (showing once — vault it now): {password}"))
        except Exception as e:
            print(red(f"  PFX bundling failed: {e}"))
            return
    print("\n[4/6] Import into Firebox ...")
    for n in ("chain.pem", "cert.pem"):
        if not (live / n).is_file():
            print(red(f"  Missing {(live / n)}"))
            return
        try:
            shutil.copy2(live / n, workdir / n)
            _hand_back(workdir / n)
        except OSError as e:
            print(red(f"  Copy failed: {e}"))
            return
    pems = [("chain.pem", "CA chain"), ("cert.pem", "server certificate")]
    lip = _local_ip_for(sess.host)
    tftp: TFTPServer | None = None
    auto = False
    if sess.prompt == "WG#" and lip is not None:
        tftp = TFTPServer(workdir, allow=tuple(n for n, _ in pems), port=69)
        if tftp.start():
            auto = True
        else:
            print(red(f"  TFTP bind failed ({tftp.error}) — manual import instead."))
            tftp = None
    auto_ok = False
    pfx_gate = False
    if auto:
        res = _auto_pem_loop(sess, tftp, lip, pems, workdir, live, domain)
        if not res:
            return
        auto_ok = True  # every import backend-checked; no need to ask again
        if res == "bundle":
            pass  # key attached via bundle; .pfx gate stays skipped
        else:
            pfx_gate = pfx_fresh or res == "partial"
    else:
        print("  CLI takes PEM only (.pfx rejected) — choose:")
        print("  1) CLI import, PEM files one by one via TFTP (chain, then cert)")
        print("  2) Web UI / WSM import of the .pfx (attaches the private key)")
        _drain_stdin()
        path = input("  Choice [1]: ").strip() or "1"
        if path == "2":
            print("  Web UI: System > Certificates > Import > select "
                  f"{pfx.name} > password from [3/6].")
            print("  WSM: Manage Device Certificates > Import > same file + password.")
        elif path == "1":
            print("  If the box demands a root CA first, paste its %Error here.")
            root = _stage_root(workdir)
            if root:
                pems.insert(0, (root, "root CA (first)"))
            if lip is not None:
                tftp = TFTPServer(workdir, allow=tuple(n for n, _ in pems), port=69)
                if tftp.start():
                    print(green(f"  Serving PEMs at tftp://{lip}/<file> (read-only, these files only)."))
                else:
                    print(red(f"  TFTP bind failed ({tftp.error}). Re-run with sudo, or stage files manually."))
                    tftp = None
            else:
                print(red("  No LAN IP found — stage PEM files on FTP/TFTP manually."))
            pfx_gate = pfx_fresh
            if not _manual_pem_loop(sess, tftp, lip, pems):
                return
        else:
            print("Unknown choice.")
            return
    if pfx_gate:
        print("  NOTE: CLI imports certificate data only — the private key attaches")
        print("  via the .pfx, so finish with Web UI/WSM for a working web cert.")
        _drain_stdin()
        if input("  Also imported the .pfx via Web UI/WSM? [y/N]: ").strip().lower() not in ("y", "yes"):
            print("  Paused. Import the .pfx via Web UI/WSM, then re-run option 2 to verify.")
            return
    if not auto_ok:
        _drain_stdin()
        if input("  Import done on the Firebox? [y/N]: ").strip().lower() not in ("y", "yes"):
            print("  Paused. Re-run option 2 after importing.")
            return
    print("\n[5/6] Verify import ...")
    out = _run_or_dead(sess, "show certificate", timeout=60.0)
    if out is None:
        return
    if domain.lower() in out.lower():
        print(green(f"  Verified: {domain} now listed on the Firebox."))
    else:
        print(yellow(f"  Not seeing {domain} under `show certificate` — double-check the import."))
        return
    print("\n[6/6] Make it the web server cert ...")
    if sess.prompt == "WG#":
        print("  Admin session — selecting directly (with confirmation).")
        if not _auto_select(sess, domain):
            return
    else:
        print("  In the admin session: configure  →  web-server-cert ?")
        print("  (lists options on your version), select the imported cert;")
        print("  alt: Web UI System > Certificates > Web Server Certificate > Save.")
        _drain_stdin()
        if input("  New cert selected as web server cert? [y/N]: ").strip().lower() not in ("y", "yes"):
            print("  Paused. Re-run option 2 after selecting it.")
            return
    print()
    for _ in range(5):
        try:
            st = assess_firebox(sess)
        except ConnectionError:
            raise
        except Exception as e:
            print(red(f"  re-assess failed: {e}"))
            return
        det = st.get("detail", {}) or {}
        blob = f"{st.get('subject', '')} {det.get('dns name', '')} {det.get('subject alt', '')}".lower()
        if domain.lower() in blob and st.get("category") in (
                "letsencrypt-valid", "letsencrypt-expiring", "third-party-valid"):
            print(green(f"  Verified: {domain} is the active web server certificate."))
            break
        print(yellow(f"  Active cert is [{st.get('cert_id', '?')}] "
                     f"{st.get('subject', '?')} — not {domain} yet."))
        if input("  Re-check? [y/N]: ").strip().lower() not in ("y", "yes"):
            print("  Paused. Re-run option 2 after selecting it.")
            return
    else:
        print(yellow("  Still not active after 5 checks — verify the selection manually."))
        return
    if staging:
        print(yellow("  Staging is NOT trusted — repeat with production before going live."))


def renewal_flow(status: dict) -> None:
    """Expired/expiring LE path with same-subject re-import warning."""
    cid = status.get("cert_id", "?")
    print()
    print("--- Renew expired/expiring Let's Encrypt certificate ---")
    print(red("WARNING: Fireware can refuse to import a new certificate with the SAME "
              "subject while the old one is still installed."))
    print("Required workaround:")
    print("  1. Web UI: System > Certificates > Web Server Certificate >")
    print("     temporarily select the default SELF-SIGNED cert > Save.")
    print(f"  2. Delete the expired cert [{cid}]: System > Certificates > select > Remove")
    print("     (or CLI equivalent — confirm exact syntax on your Fireware version).")
    print("  3. Renew below, import the new .pfx, re-select it as web server cert.")
    print()
    ok = input("Confirm you reverted to self-signed and deleted "
               f"cert [{cid}] (type YES to continue): ").strip()
    if ok != "YES":
        print("Aborted. No changes made. Re-run after the revert+delete steps.")
        return
    detail = status.get("detail", {}) or {}
    default_domain = (detail.get("dns name", "") or "").split()
    subj = status.get("subject", "") or ""
    m = re.search(r"cn\s*=\s*([A-Za-z0-9._*-]+)", subj, re.I)
    domain = (default_domain[0] if default_domain else (m.group(1) if m else ""))
    domain = _prompt_domain(domain)
    email = _prompt_email()
    staging_in = input("Use STAGING first (recommended)? [y/N]: ").strip().lower()
    staging = staging_in in ("y", "yes")
    if not need_bin("certbot") or not need_bin("openssl"):
        print(red("Need both certbot and openssl binaries for renewal."))
        return
    print("\nRunning certbot --force-renewal (HTTP-01, needs port 80)...")
    go = input("Run now? [y/N]: ").strip().lower()
    if go not in ("y", "yes"):
        print("Skipped. Manual:")
        print(f"  sudo certbot certonly --force-renewal --standalone -d {domain}")
        return
    try:
        certbot_renew(domain, staging=staging)
        print(green("  renewed."))
    except Exception as e:
        print(red(f"  {e}"))
        return
    live = Path(f"/etc/letsencrypt/live/{domain}")
    fullchain, privkey = live / "fullchain.pem", live / "privkey.pem"
    workdir = OUT / "certs" / domain
    password = gen_pfx_password(32)
    pfx = workdir / f"{domain}-renewed.pfx"
    try:
        make_pfx(fullchain, privkey, pfx, password)
        (workdir / f"{domain}-renewed.pfx.password.txt").write_text(password + "\n")
        try:
            (workdir / f"{domain}-renewed.pfx.password.txt").chmod(0o600)
        except OSError:
            pass
        _hand_back(pfx)
        _hand_back(workdir / f"{domain}-renewed.pfx.password.txt")
        print(green(f"  pfx: {_short(pfx)}"))
        print(yellow(f"  PFX password (showing once — vault it now): {password}"))
    except Exception as e:
        print(red(f"  PFX bundling failed: {e}"))
        return
    print("\nFinish in Web UI:")
    print(f"  1. Import {pfx.name} with the password above.")
    print("  2. Web Server Certificate > select new cert > Save.")
    print("  3. Re-run Assess (menu 3) to verify.")


def install_menu(sess: FireboxSession, last_status: dict | None) -> dict | None:
    status = last_status or assess_firebox(sess)
    cat = status.get("category", "unknown")
    print(color_for_category(cat, f"Status: {status.get('summary', '?')}\n"))
    if cat == "self-signed":
        if input("Proceed to issuance? [y/N]: ").strip().lower() in ("y", "yes"):
            issuance_flow(sess, status)
        return status
    if cat in ("letsencrypt-expired", "third-party-expired"):
        if input("Proceed to renewal? [y/N]: ").strip().lower() in ("y", "yes"):
            renewal_flow(status)
        return status
    if cat == "letsencrypt-expiring":
        if input("Proceed to renewal? [y/N]: ").strip().lower() in ("y", "yes"):
            renewal_flow(status)
        return status
    if cat in ("letsencrypt-valid", "third-party-valid"):
        print(green("Nothing to do — certificate is valid."))
        return status
    print("Unclassified state — use Show menu to inspect manually.")
    return status


def show_menu(sess: FireboxSession):
    last_status: dict | None = None
    try:
        print("Auto-assessing web server certificate ...")
        print()
        last_status = assess_firebox(sess)
    except ConnectionError:
        return
    except Exception as e:
        print(red(f"auto-assess failed: {e}"))
        print()
    while True:
        print("1) Show certificates")
        print("2) Issue / renew Let's Encrypt certificate")
        print("3) Re-assess web server certificate")
        print("0) Exit")
        print()
        try:
            choice = input("Select [1]: ").strip() or "1"
        except (EOFError, KeyboardInterrupt):
            print()
            return
        if choice == "0":
            return
        print()
        if choice == "3":
            try:
                last_status = assess_firebox(sess)
            except ConnectionError:
                return
            except Exception as e:
                print(red(f"assess failed: {e}"))
                print()
            continue
        if choice == "2":
            try:
                last_status = install_menu(sess, last_status)
            except ConnectionError:
                return
            except Exception as e:
                print(red(f"install step failed: {e}"))
            print()
            continue
        if choice != "1":
            print("Unknown option.")
            print()
            continue
        # Show submenu
        print("Show certificates:")
        print("  1) Show certificate")
        print("  2) Syntax help")
        print("  3) Detail by ID")
        print("  4) Active web server certificate")
        print()
        try:
            sub = input("Select [1]: ").strip() or "1"
        except (EOFError, KeyboardInterrupt):
            print()
            return
        print()
        if sub == "2":
            # Static text (observed on 12.12.3): querying '?' on the device
            # leaves a partial input line that corrupts the next command.
            print("show certificate ?")
            print("  <cr>         Carriage return")
            print("  <int>        Certificate ID  <10000-99999>")
            print("  fingerprint  Certificate Fingerprint")
            print("  name         Name of the entity")
            print("  type         Show the certificates by type")
            print()
        elif sub == "3":
            try:
                cid = input("Certificate ID [29000]: ").strip() or "29000"
            except (EOFError, KeyboardInterrupt):
                print()
                return
            print()
            out = _run_or_dead(sess, f"show certificate {cid}", timeout=20.0)
            if out is None:
                return
            print(out)
            print()
        elif sub == "4":
            out = _run_or_dead(sess, "show web-server-cert", timeout=20.0)
            if out is None:
                return
            print(out)
            print()
        elif sub == "1":
            out = _run_or_dead(sess, "show certificate", timeout=60.0)
            if out is None:
                return
            print(out)
            print()
        else:
            print("Unknown option.")
            print()


def connect_firebox(host: str, port: int, user: str, pw: str = "") -> FireboxSession | None:
    """Prompt for password (unless given, never stored) + connect.

    Prints friendly errors instead of tracebacks. Returns the session,
    or None on any failure (caller should exit non-zero).
    """
    if not pw:
        try:
            pw = getpass.getpass(f"Password for {user} (not stored): ")
        except (KeyboardInterrupt, EOFError):
            print("\nCancelled.")
            return None
    try:
        return FireboxSession(host, port, user, pw)
    except TimeoutError as e:
        print()
        print(red(f"CONNECTION FAILED: {e}"))
        print()
        print("Check: host/port reachable, SSH policy allows it, username/password correct.")
        print("No changes were made.")
        print()
        return None
    except (OSError, EOFError) as e:
        print()
        print(red(f"CONNECTION FAILED: {e}"))
        print("Check: host/port reachable and SSH service responding.")
        print()
        return None
    except KeyboardInterrupt:
        print("\nCancelled.")
        print()
        return None
    finally:
        pw = ""


def _monitor_rc(cat: str) -> int:
    """Exit code for --showonly: 0 valid, 1 needs attention, 2 error/unknown."""
    if cat in ("letsencrypt-valid", "third-party-valid"):
        return 0
    if cat == "unknown":
        return 2
    return 1


def main() -> int:
    p = argparse.ArgumentParser(
        prog="acme.py",
        usage="%(prog)s [-h HOST] [-p PORT] [-u USER] [--tui] [--showonly]",
        description=("Let's Encrypt Certificate Generation (locally-managed)\n"
                     "TUI wizard for locally-managed WatchGuard Fireboxes over SSH."),
        epilog=("examples:\n"
                "  python3 acme.py --showonly\n"
                "  sudo python3 acme.py -u admin --tui"),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=False)
    p.add_argument("--help", action="help", help="show this help message and exit")
    g = p.add_argument_group("connection")
    g.add_argument("-h", "--host", metavar="HOST", default=os.getenv("FB_HOST", DEFAULT_HOST),
                   help=f"Firebox IP address or FQDN (default {DEFAULT_HOST})")
    g.add_argument("-p", "--port", metavar="PORT", type=int,
                   default=int(os.getenv("FB_PORT", str(DEFAULT_PORT))),
                   help=f"SSH port (default {DEFAULT_PORT})")
    g.add_argument("-u", "--user", metavar="USER", default=os.getenv("FB_USER", DEFAULT_USER),
                   help=f"SSH username (default {DEFAULT_USER})")
    m = p.add_argument_group("mode")
    m.add_argument("--tui", action="store_true", help="interactive menu (default)")
    m.add_argument("--showonly", action="store_true", help="print only the certificate assessment, then exit")
    args = p.parse_args()
    args.password = ""

    host, port, user = args.host or DEFAULT_HOST, args.port, args.user

    if args.showonly:
        print(f"\nConnecting to {user}@{host}:{port} ...")
        sess = connect_firebox(host, port, user)
        if sess is None:
            return 2
        print()
        set_title(f"CONNECTED {user}@{host}:{port}")
        print(green("CONNECTED"))
        print()
        rc = 2
        try:
            status = assess_firebox(sess)
            rc = _monitor_rc(status.get("category", "unknown"))
        except ConnectionError:
            rc = 2
        except (KeyboardInterrupt, EOFError):
            print("\nCancelled.")
            rc = 130
        finally:
            sess.close()
            set_title("acme")
            print(red("DISCONNECTED"))
        return rc

    args = tui_wizard(args)  # the menu is the interface; --tui is a no-op alias
    host, port, user = args.host or DEFAULT_HOST, args.port, args.user

    print(f"\nConnecting to {user}@{host}:{port} ...")
    pw = getattr(args, "password", "")
    sess = connect_firebox(host, port, user, pw)
    args.password = ""
    pw = ""
    if sess is None:
        print("Re-run with: python3 acme.py --tui")
        print()
        return 1
    print()
    set_title(f"CONNECTED {user}@{host}:{port}")
    print(green("CONNECTED"))
    if os.geteuid() != 0:
        print(yellow("Running without root — assess works; issuance needs sudo (ports 80/69, /etc/letsencrypt)."))
    print()
    try:
        show_menu(sess)
    except (KeyboardInterrupt, EOFError):
        print("\nCancelled.")
    finally:
        sess.close()
        set_title("acme")
        print()
        print(red("DISCONNECTED"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
