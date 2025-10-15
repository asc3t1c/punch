# punch
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
