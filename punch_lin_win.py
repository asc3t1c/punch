#!/usr/bin/python
"""
punch.py by nu11secur1ty 2025 (upgraded)

Interactive multi-hash helper for legitimate recovery/testing of hashes you own.
Supports: md5, sha1, sha256, sha512, ntlm, bcrypt (bcrypt optional).

Adds:
 - Resume support for dictionary (dict_progress.txt), mask (mask_progress.txt) and brute-force (punch_progress.txt)
 - Logs found plaintexts to found.txt with encoding information (utf-8 / utf-8+nl / utf-16le / utf-16le+nl)
 - Live candidate printing (throttled)
 - Graceful Ctrl+C with state save
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


def log_found(algo: str, target_hash: str, candidate: str, raw_bytes: bytes, encoding: str) -> None:
    """Append a found result to found.txt with timestamp and encoding used."""
    found_file = "found.txt"
    try:
        ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        with open(found_file, "a", encoding="utf-8") as ff:
            ff.write(f"{ts} | {algo} | {target_hash} | {encoding} | {candidate}\n")
    except Exception as e:
        print(f"[!] Could not write to {found_file}: {e}")


def check_candidate(candidate: str, target_hash: str, algo: str,
                    try_newline: bool = False, try_utf16le: bool = False
                    ) -> Optional[Tuple[str, bytes, str]]:
    """
    Try candidate in a few common encodings and return (candidate, bytes, encoding)
    on match, otherwise None.

    encoding labels:
      'utf-8', 'utf-8+nl', 'utf-16le', 'utf-16le+nl'
    """
    algo = algo.lower()
    variants: list[Tuple[bytes, str]] = []

    # utf-8
    try:
        b = candidate.encode("utf-8")
        variants.append((b, "utf-8"))
        if try_newline:
            variants.append(((candidate + "\n").encode("utf-8"), "utf-8+nl"))
    except Exception:
        pass

    # utf-16le
    if try_utf16le or algo == "ntlm":
        try:
            b = candidate.encode("utf-16le")
            variants.append((b, "utf-16le"))
            if try_newline:
                variants.append(((candidate + "\n").encode("utf-16le"), "utf-16le+nl"))
        except Exception:
            pass

    for b, enc in variants:
        if algo == "bcrypt":
            if not HAS_BCRYPT:
                continue
            try:
                if bcrypt.checkpw(b, target_hash.encode() if isinstance(target_hash, str) else target_hash):
                    return candidate, b, enc
            except Exception:
                pass
        else:
            try:
                if digest_hex(b, algo) == target_hash.lower():
                    return candidate, b, enc
            except Exception:
                pass
    return None


# -------------------------
# Attack modes
# -------------------------
def dictionary_attack(target_hash: str, algo: str, wordlist_path: str,
                      try_newline: bool = False, try_utf16le: bool = False,
                      resume_mode: bool = False) -> Optional[str]:
    """
    Dictionary attack with optional resume support.
    Resume method: save the last tested candidate string to dict_progress.txt.
    When resuming, we skip until that string is seen, then continue.
    """
    if not os.path.isfile(wordlist_path):
        print("Wordlist not found:", wordlist_path)
        return None

    progress_file = "dict_progress.txt"
    resume_from: Optional[str] = None
    if resume_mode and os.path.exists(progress_file):
        try:
            with open(progress_file, "r", encoding="utf-8") as pf:
                resume_from = pf.readline().strip()
                if resume_from:
                    print(f"[+] Will resume dictionary from saved candidate: '{resume_from}'")
        except Exception as e:
            print(f"[!] Could not read {progress_file}: {e}")

    start = time.time()
    checked = 0
    found_resume_marker = resume_from is None  # True means we're ready to test; False means skip until resume_from

    try:
        with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                if stop_event.is_set():
                    print("\nDictionary attack interrupted by user.")
                    break
                candidate = line.rstrip("\r\n")
                if not found_resume_marker:
                    # skip until we reach the saved spot
                    if candidate == resume_from:
                        found_resume_marker = True
                    continue

                checked += 1
                # periodic status
                if checked % 100000 == 0:
                    elapsed = time.time() - start
                    print(f"Checked {checked:,} words ({checked/elapsed:.1f} w/s)")

                # check candidate
                res = check_candidate(candidate, target_hash, algo, try_newline, try_utf16le)
                if res:
                    cand, raw, enc = res
                    print(f"[+] FOUND: '{cand}'  encoding={enc}  bytes={raw!r}")
                    log_found(algo, target_hash, cand, raw, enc)
                    # remove progress file on success
                    try:
                        if os.path.exists(progress_file):
                            os.remove(progress_file)
                    except Exception:
                        pass
                    return cand

                # save progress occasionally (every 50k)
                if checked % 50000 == 0:
                    try:
                        with open(progress_file, "w", encoding="utf-8") as pf:
                            pf.write(candidate)
                    except Exception as e:
                        print(f"[!] Could not write {progress_file}: {e}")

    finally:
        elapsed = time.time() - start
        print(f"Dictionary attack stopped after {checked:,} checks in {elapsed:.1f}s.")
        # save last candidate (if any) for resume
        try:
            if candidate:
                with open(progress_file, "w", encoding="utf-8") as pf:
                    pf.write(candidate)
        except Exception:
            pass
    print("Not found in wordlist.")
    return None


def _mask_to_parts(mask: str) -> list[list[str]]:
    mapping = {
        "?l": list(string.ascii_lowercase),
        "?u": list(string.ascii_uppercase),
        "?d": list(string.digits),
        "?s": list(string.punctuation),
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
        parts.append([mask[i]])
        i += 1
    return parts


def mask_attack(target_hash: str, algo: str, mask: str,
                try_newline: bool = False, try_utf16le: bool = False,
                resume_mode: bool = False) -> Optional[str]:
    """
    Mask attack with optional resume support.
    Resume method: save last candidate string to mask_progress.txt; on resume skip until seen.
    """
    parts = _mask_to_parts(mask)
    progress_file = "mask_progress.txt"
    resume_from: Optional[str] = None
    if resume_mode and os.path.exists(progress_file):
        try:
            with open(progress_file, "r", encoding="utf-8") as pf:
                resume_from = pf.readline().strip()
                if resume_from:
                    print(f"[+] Will resume mask attack from saved candidate: '{resume_from}'")
        except Exception as e:
            print(f"[!] Could not read {progress_file}: {e}")

    total = 0
    start = time.time()
    found_resume_marker = resume_from is None

    try:
        for tup in itertools.product(*parts):
            if stop_event.is_set():
                print("\nMask attack interrupted by user.")
                break
            candidate = "".join(tup)
            if not found_resume_marker:
                if candidate == resume_from:
                    found_resume_marker = True
                continue

            total += 1
            if total % 200000 == 0:
                elapsed = time.time() - start
                print(f"Checked {total:,} candidates ({total/elapsed:.1f} c/s), last='{candidate}'")

            res = check_candidate(candidate, target_hash, algo, try_newline, try_utf16le)
            if res:
                cand, raw, enc = res
                print(f"[+] FOUND: '{cand}'  encoding={enc}  bytes={raw!r}")
                log_found(algo, target_hash, cand, raw, enc)
                try:
                    if os.path.exists(progress_file):
                        os.remove(progress_file)
                except Exception:
                    pass
                return cand

            # save progress every 100k
            if total % 100000 == 0:
                try:
                    with open(progress_file, "w", encoding="utf-8") as pf:
                        pf.write(candidate)
                except Exception as e:
                    print(f"[!] Could not write {progress_file}: {e}")

    finally:
        elapsed = time.time() - start
        print(f"Mask attack stopped after {total:,} checks in {elapsed:.1f}s.")
        # save last candidate if exists
        try:
            if candidate:
                with open(progress_file, "w", encoding="utf-8") as pf:
                    pf.write(candidate)
        except Exception:
            pass
    print("Mask finished; not found.")
    return None


#--------------------------------
# Brute-force with resume support
#--------------------------------
def brute_force(target_hash: str, algo: str, charset: str, max_len: int,
                try_newline: bool = False, try_utf16le: bool = False,
                resume_mode: bool = False) -> Optional[str]:
    progress_file = "punch_progress.txt"
    found_file = "found.txt"
    resume_from = None
    if resume_mode and os.path.exists(progress_file):
        try:
            with open(progress_file, "r", encoding="utf-8") as pf:
                line = pf.readline().strip()
                if line:
                    resume_from = line
                    print(f"[+] Resuming from last candidate: '{resume_from}'")
        except Exception as e:
            print(f"[!] Could not read progress file: {e}")

    print(f"Starting brute-force: charset size={len(charset)} max_len={max_len}")
    total = 0
    start = time.time()
    prev_candidate = ""
    last_display_time = 0.0
    found_resume = not resume_mode  # becomes True once resume candidate is reached

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
                if resume_mode and not found_resume:
                    if candidate == resume_from:
                        # Found the saved point — resume after it
                        found_resume = True
                    continue

                total += 1

                # Live small update: display candidate and last-changed char (throttled)
                if prev_candidate:
                    changed_symbol = None
                    changed_pos = None
                    maxl = max(len(prev_candidate), len(candidate))
                    for i in range(maxl):
                        a = prev_candidate[i] if i < len(prev_candidate) else None
                        b = candidate[i] if i < len(candidate) else None
                        if a != b:
                            changed_pos = i
                            changed_symbol = b
                    now = time.time()
                    if now - last_display_time >= 0.05:
                        sys.stdout.write(
                            f"\rTesting: {candidate} (changed '{changed_symbol}' at pos {changed_pos})     "
                        )
                        sys.stdout.flush()
                        last_display_time = now
                else:
                    sys.stdout.write(f"\rTesting: {candidate}   ")
                    sys.stdout.flush()

                prev_candidate = candidate

                # Save progress every 10k attempts
                if total % 10000 == 0:
                    try:
                        with open(progress_file, "w", encoding="utf-8") as pf:
                            pf.write(candidate)
                    except Exception as e:
                        print(f"\n[!] Could not write progress file: {e}")

                # Periodic full-line status
                if total % 200000 == 0:
                    elapsed = time.time() - start
                    sys.stdout.write("\n")
                    print(f"Checked {total:,} ({total/elapsed:.1f} c/s), last='{candidate}'")

                # Check candidate
                res = check_candidate(candidate, target_hash, algo, try_newline, try_utf16le)
                if res:
                    cand, raw, enc = res
                    sys.stdout.write("\n")
                    print(f"[+] FOUND: '{cand}'  encoding={enc}  bytes={raw!r}")

                    # Append result to found.txt
                    try:
                        ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
                        with open(found_file, "a", encoding="utf-8") as ff:
                            ff.write(f"{ts} | {algo} | {target_hash} | {enc} | {cand}\n")
                        print(f"[+] Logged result to {found_file}")
                    except Exception as e:
                        print(f"[!] Could not write found file: {e}")

                    # Remove progress file (we finished)
                    try:
                        if os.path.exists(progress_file):
                            os.remove(progress_file)
                    except Exception:
                        pass

                    return cand

            if stop_event.is_set():
                break

    except KeyboardInterrupt:
        print("\nBrute-force stopped by user (Ctrl+C).")
        stop_event.set()
    except Exception as e:
        print(f"\nError during brute-force: {e}")
    finally:
        # Save last candidate to progress file so we can resume next run
        if prev_candidate:
            try:
                with open(progress_file, "w", encoding="utf-8") as pf:
                    pf.write(prev_candidate)
                print(f"\n[+] Progress saved: '{prev_candidate}' -> {progress_file}")
            except Exception as e:
                print(f"[!] Could not save progress: {e}")

        elapsed = time.time() - start
        print(f"\nBrute-force stopped after {total:,} checks in {elapsed:.1f}s.")

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
        return True
    h = h.strip().lower()
    return all(c in "0123456789abcdef" for c in h)


def main() -> None:
    print("Multi-Hash Cracker (upgraded, interactive)")
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
        " 3) Brute-force (start fresh)\n"
        " 4) Brute-force (resume from last progress)\n"
    )
    mode = prompt("Mode (1-4): ", "1")

    try_utf16le = prompt("Try UTF-16LE variants? (y/N): ", "N").lower() == "y"
    try_newline = prompt("Try with trailing newline? (y/N): ", "N").lower() == "y"

    if mode == "1":
        wl = prompt("Path to wordlist (e.g., rockyou.txt): ").strip()
        if not wl or not os.path.isfile(wl):
            print("Wordlist missing. Exiting.")
            return
        # allow resume if progress file exists
        dict_progress = "dict_progress.txt"
        resume_dict = False
        if os.path.exists(dict_progress):
            yn = prompt("Resume dictionary attack from saved progress? (y/N): ", "N").lower()
            resume_dict = (yn == "y")
        dictionary_attack(target_hash, algo, wl, try_newline, try_utf16le, resume_mode=resume_dict)

    elif mode == "2":
        mask = prompt("Enter mask (e.g. '?u?l?l?l?d?d'): ").strip()
        if not mask:
            print("No mask. Exiting.")
            return
        mask_progress = "mask_progress.txt"
        resume_mask = False
        if os.path.exists(mask_progress):
            yn = prompt("Resume mask attack from saved progress? (y/N): ", "N").lower()
            resume_mask = (yn == "y")
        mask_attack(target_hash, algo, mask, try_newline, try_utf16le, resume_mode=resume_mask)

    elif mode == "3" or mode == "4":
        resume_option = (mode == "4")
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

        # If user chose start fresh but progress file exists, prompt to resume
        progress_file = "punch_progress.txt"
        if not resume_option and os.path.exists(progress_file):
            print("\nSaved brute-force progress found.")
            print(" 1) Start fresh (ignore saved progress)")
            print(" 2) Continue from saved progress")
            choice = prompt("Choice (1-2): ", "1")
            if choice == "2":
                resume_option = True
                print("[+] Will resume saved progress.")
            else:
                print("[+] Starting fresh (ignoring saved progress).")

        print("Confirm start brute-force? This can be expensive. (y/N)")
        if prompt("> ", "N").lower() != "y":
            print("Cancelled.")
            return

        brute_force(target_hash, algo, charset, max_len, try_newline, try_utf16le, resume_option)

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
