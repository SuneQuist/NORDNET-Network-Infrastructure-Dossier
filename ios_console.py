"""Restricted Telnet-console transport for local GNS3 IOSv (Python 3.12 only).

Not for real device management. GNS3 Telnet consoles are plaintext and should
be reachable only on a trusted local lab network.
"""
from __future__ import annotations
import re
import time
import warnings

PROMPT = re.compile(r"^[A-Za-z0-9_.-]+(?:\([^()\n]+\))?[>#]$")
CMD_ERROR = re.compile(
    r"(?im)^\s*%\s*(?:Invalid input|Incomplete command|Ambiguous command|"
    r"Command rejected|Unrecognized command|Unknown command|Error\b|"
    r"Cannot|Not allowed|Permission denied)"
)
FIRST_DIALOG = re.compile(r"Would you like to enter the initial configuration dialog\?\s*\[yes/no\]:?\s*$", re.I)
BOOT_ENTER = re.compile(r"Press (?:RETURN|ENTER) to get started!?", re.I)


def last_line(raw):
    text = raw.decode("utf-8", errors="replace") if isinstance(raw, (bytes, bytearray)) else str(raw)
    text = re.sub(r"\x1b\[[0-9;?]*[ -/]*[@-~]", "", text)
    return next((line.strip() for line in reversed(text.replace("\r", "").split("\n")) if line.strip()), "")


def recv_prompt(tn, timeout=35, first_boot=False):
    """Wait for a stable prompt; recover from late unsolicited IOS syslog lines."""
    deadline = time.monotonic() + timeout
    started = last_rx = last_nudge = time.monotonic()
    last_report = started
    buf = bytearray()
    last_action = None
    while time.monotonic() < deadline:
        try:
            chunk = tn.read_very_eager()
        except EOFError as exc:
            raise RuntimeError("Cisco console disconnected") from exc
        now = time.monotonic()
        if chunk:
            buf.extend(chunk)
            last_rx = now
            if len(buf) > 1_500_000:
                raise RuntimeError("Cisco console output exceeded safe buffer")
        tail = last_line(buf)
        if FIRST_DIALOG.search(tail):
            if not first_boot:
                raise RuntimeError("Unexpected IOS initial configuration dialog")
            if last_action != ("no", tail):
                tn.write(b"no\r\n")
                last_action = ("no", tail)
        elif BOOT_ENTER.search(tail):
            if not first_boot:
                raise RuntimeError("Unexpected IOS boot dialog")
            if last_action != ("enter", tail):
                tn.write(b"\r\n")
                last_action = ("enter", tail)
        elif tail.lower().endswith("password:") or re.search(r"\[yes/no\]:?$", tail, re.I):
            raise RuntimeError(f"Unexpected interactive console prompt: {tail}")
        elif PROMPT.fullmatch(tail) and now - last_rx >= 0.3:
            return buf.decode("utf-8", errors="replace")
        elif (now - last_rx >= (3.0 if first_boot else 0.8)
              and now - last_nudge >= (5.0 if first_boot else 1.5)):
            # While IOSv is booting, Enter is harmless. Never give up merely
            # because a certain number of empty prompts were sent.
            tn.write(b"\r\n")
            last_nudge = now
        if first_boot and now - last_report >= 20:
            print(f"  Waiting for IOS CLI ({int(now - started)}s); latest output: {tail[-100:]!r}", flush=True)
            last_report = now
        time.sleep(0.06)
    raise RuntimeError(f"IOS prompt not recovered within {timeout}s; last line={last_line(buf)!r}")


def command(tn, cmd, timeout=35):
    tn.write(cmd.encode("ascii") + b"\r\n")
    out = recv_prompt(tn, timeout)
    if CMD_ERROR.search(out):
        raise RuntimeError(f"IOS rejected {cmd!r}: {out[-800:]}")
    return out


def open_console(host, port, boot_timeout=360):
    import sys
    if sys.version_info[:2] != (3, 12):
        raise RuntimeError("Console transport needs Python 3.12; run py -3.12")
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        import telnetlib
    deadline = time.monotonic() + boot_timeout
    last = None
    while time.monotonic() < deadline:
        tn = None
        try:
            tn = telnetlib.Telnet(host, int(port), timeout=5)
            tn.write(b"\r\n")
            # A fresh IOSv under Hyper-V can take substantially longer than
            # 25 seconds to finish booting. Wait for the actual CLI prompt.
            remaining = max(1, deadline - time.monotonic())
            prompt = last_line(recv_prompt(tn, timeout=remaining, first_boot=True))
            if "(config" in prompt:
                prompt = last_line(command(tn, "end"))
            if prompt.endswith(">"):
                prompt = last_line(command(tn, "enable"))
            if not prompt.endswith("#") or "(config" in prompt:
                raise RuntimeError(f"Expected privileged EXEC, received {prompt!r}")
            command(tn, "terminal length 0")
            return tn
        except (OSError, EOFError, TimeoutError, RuntimeError) as exc:
            last = exc
            if tn is not None:
                tn.close()
            if time.monotonic() < deadline:
                time.sleep(min(2, max(0, deadline - time.monotonic())))
    raise RuntimeError(f"Unable to reach IOS console {host}:{port} after {boot_timeout}s: {last}")


def console_host(node, compute_host):
    host = node.get("console_host")
    return compute_host if not host or host in {"0.0.0.0", "::", "127.0.0.1"} else host
