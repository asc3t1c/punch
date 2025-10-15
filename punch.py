#!/usr/bin/python
"""
punch.py by nu11secur1ty — polished version

Interactive multi-hash helper for legitimate recovery/testing of hashes you own.
Supports: md5, sha1, sha256, sha512, ntlm, bcrypt (bcrypt optional).

Modes:
  - dictionary attack (wordlist)
  - mask attack (simple masks like '?u?l?l?d?d')
  - brute-force (small search space)

Notes:
 - MD4 is implemented here so NTLM (MD4(utf-16le(password))) can be tested.
 - bcrypt support requires `pip install bcrypt`. If not installed, bcrypt mode is disabled.
 - Use only on hashes you are authorized to test.
"""

from __future__ import annotations

import hashlib
import itertools
import string
import sys
import os
import time
import threading
import signal
from typing import Optional, Tuple

# optional bcrypt support
try:
    import bcrypt  # type: ignore
    HAS_BCRYPT = True
except Exception:
    HAS_BCRYPT = False

# -------------------------
# Ctrl+C / graceful stop
# -------------------------
stop_event = threading.Event()


def _signal_handler(signum, frame) -> None:
    print("\nSIGINT received — attempting graceful shutdown...")
    stop_event.set()


signal.signal(signal.SIGINT, _signal_handler)


# -------------------------
# Small MD4 implementation
# -------------------------
def _left_rotate(x: int, n: int) -> int:
    return ((x << n) & 0xFFFFFFFF) | (x >> (32 - n))


def md4(data: bytes) -> bytes:
    """Return 16-byte MD4 digest (for NTLM)."""
    msg = bytearray(data)
    orig_len_bits = (8 * len(msg)) & 0xFFFFFFFFFFFFFFFF
    msg.append(0x80)
    while (len(msg) % 64) != 56:
        msg.append(0)
    msg += orig_len_bits.to_bytes(8, "little")

    A = 0x67452301
    B = 0xEFCDAB89
    C = 0x98BADCFE
    D = 0x10325476

    def F(x, y, z): return (x & y) | (~x & z)
    def G(x, y, z): return (x & y) | (x & z) | (y & z)
    def H(x, y, z): return x ^ y ^ z

    for i in range(0, len(msg), 64):
        X = [int.from_bytes(msg[i + 4*j:i + 4*j + 4], "little") for j in range(16)]
        AA, BB, CC, DD = A, B, C, D

        # round 1
        s1 = [3, 7, 11, 19]
        for j in range(16):
            k = j
            A = _left_rotate((A + F(B, C, D) + X[k]) & 0xFFFFFFFF, s1[j % 4])
            A, B, C, D = D, A, B, C

        # round 2
        s2 = [3, 5, 9, 13]
        for j in range(16):
            k = (j % 4) * 4 + (j // 4)
            A = _left_rotate((A + G(B, C, D) + X[k] + 0x5A827999) & 0xFFFFFFFF, s2[j % 4])
            A, B, C, D = D, A, B, C

        # round 3
        s3 = [3, 9, 11, 15]
        order = [0,8,4,12,2,10,6,14,1,9,5,13,3,11,7,15]
        for j in range(16):
            k = order[j]
            A = _left_rotate((A + H(B, C, D) + X[k] + 0x6ED9EBA1) & 0xFFFFFFFF, s3[j % 4])
            A, B, C, D = D, A, B, C

        A = (A + AA) & 0xFFFFFFFF
        B = (B + BB) & 0xFFFFFFFF
        C = (C + CC) & 0xFFFFFFFF
        D = (D + DD) & 0xFFFFFFFF

    return A.to_bytes(4, "little") + B.to_bytes(4, "little") + C.to_bytes(4, "little") + D.to_bytes(4, "little")


# -------------------------
# Digest helpers
# -------------------------
def digest_hex(data_bytes: bytes, algo: str) -> str:
    algo = algo.lower()
    if algo in ("md5", "sha1", "sha224", "sha256", "sha384", "sha512"):
        h = hashlib.new(algo)
        h.update(data_bytes)
        return h.hexdigest()
    if algo in ("ntlm", "md4"):
        return md4(data_bytes).hex()
    raise ValueError(f"Unsupported algorithm for hex digest: {algo}")


def check_candidate(candidate: str, target_hash: str, algo: str,
                    try_newline: bool = False, try_utf16le: bool = False) -> Optional[Tuple[str, bytes]]:
    """
    Try candidate in a few common encodings and return (candidate, bytes) on match,
    otherwise None.
    """
    algo = algo.lower()
    variants: list[bytes] = []

    # utf-8 bytes (and optional newline)
    try:
        b = candidate.encode("utf-8")
        variants.append(b)
        if try_newline:
            variants.append((candidate + "\n").encode("utf-8"))
    except Exception:
        pass

    # utf-16le (NTLM or if requested)
    if try_utf16le or algo == "ntlm":
        try:
            b = candidate.encode("utf-16le")
            variants.append(b)
            if try_newline:
                variants.append((candidate + "\n").encode("utf-16le"))
        except Exception:
            pass

    for b in variants:
        if algo == "bcrypt":
            if not HAS_BCRYPT:
                continue
            try:
                ok = bcrypt.checkpw(b, target_hash.encode() if isinstance(target_hash, str) else target_hash)
                if ok:
                    return candidate, b
            except Exception:
                pass
        else:
            try:
                if digest_hex(b, algo) == target_hash.lower():
                    return candidate, b
            except Exception:
                pass
    return None


# -------------------------
# Attack modes
# -------------------------
def dictionary_attack(target_hash: str, algo: str, wordlist_path: str,
                      try_newline: bool = False, try_utf16le: bool = False) -> Optional[str]:
    if not os.path.isfile(wordlist_path):
        print("Wordlist not found:", wordlist_path)
        return None

    start = time.time()
    checked = 0
    try:
        with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                if stop_event.is_set():
                    print("\nDictionary attack interrupted by user.")
                    break
                candidate = line.rstrip("\r\n")
                checked += 1
                if checked % 100000 == 0:
                    elapsed = time.time() - start
                    print(f"Checked {checked:,} words ({checked/elapsed:.1f} w/s)")
                res = check_candidate(candidate, target_hash, algo, try_newline, try_utf16le)
                if res:
                    cand, raw = res
                    print(f"FOUND: '{cand}'  bytes={raw!r}")
                    return cand
    finally:
        elapsed = time.time() - start
        print(f"Dictionary attack stopped after {checked:,} checks in {elapsed:.1f}s.")
    print("Not found in wordlist.")
    return None


def _mask_to_parts(mask: str) -> list[list[str]]:
    """Convert a mask like '?u?l?d' into a list of char-lists."""
    mapping = {
        "?l": list(string.ascii_lowercase),
        "?u": list(string.ascii_uppercase),
        "?d": list(string.digits),
        "?s": list(string.punctuation),
        # all printable without control whitespace
        "?a": list("".join(ch for ch in string.printable if ch not in "\t\r\n\x0b\x0c")),
    }
    parts: list[list[str]] = []
    i = 0
    while i < len(mask):
        if mask[i] == "?" and i + 1 < len(mask):
            token = mask[i:i+2]
            if token in mapping:
                parts.append(mapping[token])
                i += 2
                continue
        # literal char
        parts.append([mask[i]])
        i += 1
    return parts


def mask_attack(target_hash: str, algo: str, mask: str,
                try_newline: bool = False, try_utf16le: bool = False) -> Optional[str]:
    parts = _mask_to_parts(mask)
    total = 0
    start = time.time()
    try:
        for tup in itertools.product(*parts):
            if stop_event.is_set():
                print("\nMask attack interrupted by user.")
                break
            candidate = "".join(tup)
            total += 1
            if total % 200000 == 0:
                elapsed = time.time() - start
                print(f"Checked {total:,} candidates ({total/elapsed:.1f} c/s), last='{candidate}'")
            res = check_candidate(candidate, target_hash, algo, try_newline, try_utf16le)
            if res:
                cand, raw = res
                print(f"FOUND: '{cand}'  bytes={raw!r}")
                return cand
    finally:
        elapsed = time.time() - start
        print(f"Mask attack stopped after {total:,} checks in {elapsed:.1f}s.")
    print("Mask finished; not found.")
    return None


def brute_force(target_hash: str, algo: str, charset: str, max_len: int,
                try_newline: bool = False, try_utf16le: bool = False) -> Optional[str]:
    print(f"Starting brute-force: charset size={len(charset)} max_len={max_len}")
    total = 0
    start = time.time()
    try:
        for length in range(1, max_len + 1):
            if stop_event.is_set():
                print(f"\nBrute-force interrupted before starting length {length}.")
                break
            print(f"Trying length {length} ...")
            for tup in itertools.product(charset, repeat=length):
                if stop_event.is_set():
                    print("\nBrute-force interrupted by user.")
                    break
                candidate = "".join(tup)
                total += 1
                if total % 200000 == 0:
                    elapsed = time.time() - start
                    print(f"Checked {total:,} ({total/elapsed:.1f} c/s), last='{candidate}'")
                res = check_candidate(candidate, target_hash, algo, try_newline, try_utf16le)
                if res:
                    cand, raw = res
                    print(f"FOUND: '{cand}'  bytes={raw!r}")
                    return cand
            if stop_event.is_set():
                break
    finally:
        elapsed = time.time() - start
        print(f"Brute-force stopped after {total:,} checks in {elapsed:.1f}s.")
    print("Brute-force finished; not found.")
    return None


# -------------------------
# CLI / interactive
# -------------------------
def prompt(prompt_text: str, default: Optional[str] = None) -> str:
    try:
        val = input(prompt_text)
    except EOFError:
        return default or ""
    return val.strip() or (default or "")


def _validate_hex_hash(h: str, algo: str) -> bool:
    if algo == "bcrypt":
        # bcrypt is not hex; skip simple validation
        return True
    h = h.strip().lower()
    return all(c in "0123456789abcdef" for c in h)


def main() -> None:
    print("Multi-Hash Cracker (polished, interactive)")
    print("Supported algorithms: md5, sha1, sha256, sha512, ntlm, bcrypt")
    algo = prompt("Algorithm: ").strip().lower()
    if algo not in ("md5", "sha1", "sha256", "sha512", "ntlm", "bcrypt"):
        print("Unsupported algorithm. Exiting.")
        return

    target_hash = prompt("Target hash (hex for digests, or bcrypt string for bcrypt): ").strip()
    if not target_hash:
        print("No hash provided. Exiting.")
        return
    if not _validate_hex_hash(target_hash, algo):
        print("Warning: hash contains non-hex characters or is malformed — double-check input.")

    print(
        "\nChoose mode:\n"
        " 1) Dictionary attack (wordlist file)\n"
        " 2) Mask attack (mask like '?u?l?l?d?d')\n"
        " 3) Brute-force (small search space)\n"
    )
    mode = prompt("Mode (1-3): ", "1")

    try_utf16le = prompt("Try UTF-16LE variants? (y/N): ", "N").lower() == "y"
    try_newline = prompt("Try with trailing newline? (y/N): ", "N").lower() == "y"

    if mode == "1":
        wl = prompt("Path to wordlist (e.g., rockyou.txt): ").strip()
        if not wl or not os.path.isfile(wl):
            print("Wordlist missing. Exiting.")
            return
        dictionary_attack(target_hash, algo, wl, try_newline, try_utf16le)

    elif mode == "2":
        mask = prompt("Enter mask (e.g. '?u?l?l?l?d?d'): ").strip()
        if not mask:
            print("No mask. Exiting.")
            return
        mask_attack(target_hash, algo, mask, try_newline, try_utf16le)

    elif mode == "3":
        print("Charset presets: 1) lowercase 2) lower+digits 3) letters+digits 4) printable")
        preset = prompt("Preset (1-4): ", "1")
        if preset == "1":
            charset = string.ascii_lowercase
        elif preset == "2":
            charset = string.ascii_lowercase + string.digits
        elif preset == "3":
            charset = string.ascii_letters + string.digits
        else:
            charset = "".join(sorted(set(string.printable)))

        try:
            max_len = int(prompt("Max length (e.g., 4): ", "3"))
        except Exception:
            print("Invalid length. Exiting.")
            return

        print("Confirm start brute-force? This can be expensive. (y/N)")
        if prompt("> ", "N").lower() != "y":
            print("Cancelled.")
            return
        brute_force(target_hash, algo, charset, max_len, try_newline, try_utf16le)

    else:
        print("Unknown mode. Exiting.")
        return

    if stop_event.is_set():
        print("\nExited early due to user interrupt (Ctrl+C). Goodbye.")
    else:
        print("\nDone.")


if __name__ == "__main__":
    if not HAS_BCRYPT:
        print("[note] 'bcrypt' python package not found; bcrypt support disabled. Install via 'pip install bcrypt' to enable.")
    main()
