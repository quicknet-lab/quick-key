# Hardware tests

The scripts work with a connected dongle (`pip install fido2 pyscard cryptography`,
plus `textual` for `tui_test.py`).
Where a script prints `PRESS BUTTON`, press BOOT when the screen asks for it.

| Script | What it checks | Presses |
|---|---|---|
| `fido_info.py` | CTAPHID, getInfo, PIN retries, U2F version, wink, vendor command | 0 |
| `fido_flow.py` | passkey (rk) with PIN, sign-in, U2F, sign-in with PIN, wrong PIN | 5 |
| `credmgmt_test.py` | credentialManagement: list, update, delete | 1 |
| `ext_test.py` | credProtect=3, hmac-secret | 3 |
| `piv_protect_test.py` | PIN-protected PIV objects: a management key stored with `ykman ... --protect` (5FC109) is unreadable without the PIN, ykman uses it with the PIN; PIV reset | 1 |
| `pgp_keep_test.py` | OpenPGP: malformed key imports are rejected and the existing key still signs; card reset | 0 |
| `review_fixes_test.py` | FIDO version from `PROJECT_VER` (CTAPHID INIT, getInfo); OpenPGP SELECT DATA (A5) with a response pending; a 4106-byte CCID message; PIV 9C PIN "always" next to 9A "once"; PIV reset | 1 |
| `fido_token_test.py` | pinUvAuthToken: one getAssertion per token, expiry if unused for 30 s, invalidated by a PIN change through PIV; largeBlobs upload survives an unauthenticated write; getPinRetries powerCycleState after 3 wrong PINs (reboots the key via `qk reboot`) | 0 |
| `apps_fixes_test.py` | OpenPGP import with a truncated 7F48 length rejected; changing a `--touch` password record (also clearing its flag) asks for the button | 2 |
| `transport_test.py` | CTAPHID: random channel IDs, unknown channel rejected, LOCK unsupported; CCID: a card reset (ICC power on) drops the PIV PIN state | 0 |
| `ctap_len_test.py` | Oversized pinHashEnc / newPinEnc / hmac-secret saltEnc are rejected before decryption (both PIN protocols), no PIN tries spent | 0 |
| `always_uv_test.py` | authenticatorConfig: alwaysUv on/off, rejection without UV, U2F gets disabled | 1 |
| `ed25519_test.py` | Ed25519 (COSE −8): registration, sign-in, rk in credentialManagement, algorithm order | 4 |
| `large_blob_test.py` | largeBlobKey, blob write/read, fragments, checksum, 2048 limit | 2 |
| `pgp_test.py` | OpenPGP: PIN, P-256 and RSA-2048 generation, signing, decryption | 0 |
| `pgp25519_test.py` | OpenPGP Ed25519/X25519: generation, signing, ECDH, import; card reset at the end | 0 |
| `gpg25519_test.sh` | Real gpg: keytocard ed25519/cv25519, decryption, signing, SSH; card reset | 0 |
| `vault_test.py` | Vault: OpenPGP — PW1/PW3 change, PW1 blocking and reset with PW3, no Reset Code; PIV — keys in all slots, PIN/PUK change, unblocking, 9E without PIN; PIV reset | 1 |
| `piv_rsa_test.py` | PIV RSA-2048: generation in 9A/9D/9E next to P-256 in 9C, certificates, decryption, 9E signing without PIN, chaining; PIV reset at the end | 1 |
| `pwd_test.py` | Password manager: device PIN, write/read/update/delete, 250 records, PIN change, blocking and unblocking with the admin PIN, generator | 3 |
| `tui_test.py` | `qk tui` via Textual Pilot (headless): wrong PIN and re-prompt, adding/editing/deleting a password via forms, PIN change, OTP via a form. Needs an empty password manager | 0 |
| `touch_test.py` | HMAC-SHA1 challenge-response (RFC 2202 vector, KeePassXC padding, behind the OATH password, delete); OpenPGP UIF on/permanent, press and timeout, cleared by a card reset; PIV version, PIN/PUK/management key metadata and the default-PIN flag, touch ALWAYS/CACHED, fixed PIN policy, slot metadata; OpenPGP card reset and PIV reset | 6 (with `--timeout`: then the LAST request, Sign?, is left unpressed for 30 s) |
| `default_pin_test.py` | **Factory reset first (erases everything).** While either PIN is the factory one: default-PIN flag in PIV metadata and ykman, FIDO getInfo forcePINChange and no pinUvAuthToken, OpenPGP key generation/import, PIV key generation and password records refused (6985); the factory value can't be set again; once both are changed (each change replaced the vault key) PIV generates and the password manager stores again. Ends with the test PINs and a P-256 key in PIV 9A | 1 |
| `devpin_test.py` | Shared PIN: a change in FIDO/OpenPGP/PIV is visible everywhere, shared counter, blocking and unblocking (PW3, PUK), admin PIN, length limits, keys and passwords survive a change; PIV reset | 1 |

All scripts expect PIN `314159` and admin PIN `27182818` and leave them
unchanged. With the factory PINs the key stores no keys or passwords: run
`default_pin_test.py` first, it resets the key and sets these PINs.
Run `gpgconf --kill scdaemon` before `pgp_test.py`.
`pgp_test.py` changes the OpenPGP keys on the card, `vault_test.py` runs
right after it (it needs those keys) and resets PIV; `pgp_keep_test.py`,
`pgp25519_test.py` and `touch_test.py` reset the OpenPGP card.
`pwd_test.py` erases all passwords on the key; `tui_test.py` needs an empty
password manager. `fido_token_test.py` reboots the key once.
