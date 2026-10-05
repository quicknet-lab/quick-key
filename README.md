# Quick-Key

Hardware security key on the LilyGO T-Dongle S3 (ESP32-S3):
FIDO2/WebAuthn (P-256 and Ed25519 passkeys, credProtect, hmac-secret, largeBlobs,
alwaysUv) and U2F, OpenPGP card (RSA, P-256, Ed25519/X25519), PIV (RSA-2048, P-256),
TOTP/HOTP, HMAC-SHA1 challenge-response (KeePassXC), password manager. OpenPGP
and PIV keys can require a button press for every use. Up to 100 passkeys (including resident SSH keys),
50 OTP accounts and 250 passwords. Confirmation is the BOOT button; the request is shown on the screen.

Changes in each version: [Releases](https://github.com/quicknet-lab/quick-key/releases).

## Install

On macOS or Linux, one command installs the `qk` tool:

```sh
curl -fsSL https://raw.githubusercontent.com/quicknet-lab/quick-key/main/install.sh | sh
```

It puts `qk` and its Python libraries into `~/.local/share/quick-key` and the
`qk` command into `~/.local/bin` (it tells you if that is not on your
`PATH`). On Linux it also installs the smart card service (`pcscd`) and a
udev rule so that the key works without root; that part asks for `sudo`.
Running the command again updates `qk`.

Requirements: Python 3.9 or newer (macOS: from python.org or Homebrew).

## First flash of a new key

A new T-Dongle S3 is flashed once through the chip's ROM bootloader:

1. Hold the BOOT button and plug the dongle in, then release the button.
2. Run `qk flash`. It downloads the latest release, checks that every image
   is signed with the Quick-Key release key, erases the dongle and writes
   the firmware.
3. Unplug the dongle and plug it in again **without** BOOT, and leave it
   plugged in. The first start takes about a minute: the chip turns on its
   protection (see [Security](#security)). Do not unplug it meanwhile.
4. `qk info` shows the version. The PINs are `123456` and `12345678`:
   change both with `qk pin change` and `qk pin change-admin`. Until then
   the key stores no keys or passwords, and browsers ask for a new PIN.

> **The first start is irreversible.** It burns Secure Boot and flash
> encryption into the chip. From then on the dongle runs only signed
> Quick-Key releases and can no longer be flashed through the ROM
> bootloader.

## Updating

```sh
qk update            # downloads the latest release; press the button when the screen asks
```

The key checks the signature, refuses images older than the running
firmware, and keeps all data. If the new firmware does not start, the key
rolls back to the previous one. `qk tui` has the same button on its Device
tab.

## Security

On its first start a released key burns into the chip's eFuses:

- **Secure Boot V2** (RSA-3072): the bootloader and the firmware must be
  signed with the Quick-Key release key, both at boot and for an update.
- **Flash encryption** (XTS-AES-256, Release mode): the flash content is
  encrypted with a key generated inside the chip, which software cannot
  read. The data store is an encrypted NVS on top of that.
- **ROM bootloader in Secure Download mode** and **JTAG disabled**: the flash
  can be neither read nor written over USB.
- **Anti-rollback**: a release that fixes a security bug can stop older
  versions from booting.
- **PINs bound to the chip**: the first start also burns an HMAC key into
  eFuse that software can use but never read. The PINs unlock the key's
  vault (OpenPGP and PIV keys, passwords) only after about a quarter of a
  second of HMACs with it, so they can't be guessed away from this chip, not
  even from a decrypted copy of the flash, and every guess on the chip costs
  that time on top of the retry counters.
- **No factory PINs in use**: while either PIN is still the default, the key
  refuses to store keys and passwords, and FIDO asks the browser to have the
  PIN changed (forcePINChange). Each PIN change in that state also replaces
  the vault key, so nothing can ever be opened with a factory PIN, not even
  an old copy left in flash; a factory value can't be chosen again.
- **An old PIN is gone for good**: the PIN records live in a partition of
  their own, not in the data store, and a PIN change erases the record under
  the old PIN from flash as soon as the new one is written and checked.
- **No logs**: a release writes nothing to the UART pins.

The bootloader turns flash encryption on in Development mode; the firmware
switches it to Release mode once it has started and a computer has seen it
over USB, so a failed first start can still be recovered. Without a secure
element the keys are as safe as the chip: protected against reading the
flash and against foreign firmware, not against lab attacks on the chip.

## Development

Requires ESP-IDF 5.3.6 (`. ~/esp/esp-idf/export.sh`).

```sh
idf.py build                                         # development build: build/quick-key.bin
idf.py -B build-secure -D QUICK_KEY_SECURE=1 build   # release build (unsigned; signed by the maintainers)
```

A development build has no Secure Boot or flash encryption and is meant for
a separate development dongle; never flash it to a released key (it would
refuse anyway). Flash it through the ROM bootloader: hold BOOT, plug in,
`idf.py -p <port> flash`, then re-plug. On a dongle that already runs a
development build, `qk update build/quick-key.bin` or
`qk update --rom build/quick-key.bin` work too. Without installing, `qk` runs
from the checkout as `python3 tools/qk.py`.

Development builds log to UART0 (GPIO43/44 on the Qwiic connector), 115200 baud.

## The `qk` tool

```sh
qk --help                       # every command also has --help
qk --version
```

🔘 marks a command that waits for the BOOT button (the screen shows what is
being confirmed), or an option after which every use needs the button.

**General**
```sh
qk tui                          # terminal UI with tabs for everything below
qk info                         # firmware version, UUID
qk reboot                       # restart the key
qk update                       # 🔘 update to the latest release, data is kept
qk update quick-key.bin         # 🔘 update from a signed image file
qk flash                        # first flash of a new key (see above; --release <dir>, --port <port>)
qk update --rom quick-key.bin   # development keys only: through the ROM bootloader (--port <port>)
qk factory-reset                # 🔘 erase everything, PINs back to the defaults
```

**PIN** — one PIN for passkeys, OpenPGP, PIV and passwords
```sh
qk pin status                   # PIN and admin PIN retries left
qk pin change                   # change the PIN (6–8 characters)
qk pin change-admin             # change the admin PIN (exactly 8 characters)
qk pin unblock                  # set a new PIN with the admin PIN
```

**Passkeys (FIDO2)**
```sh
qk fido info                    # CTAP versions, extensions, PIN state and retries
qk fido list                    # passkeys by site, with their IDs
qk fido delete <id>             # delete a passkey (ID from `qk fido list`)
qk fido reset                   # 🔘 erase all passkeys (within 10 s after plugging in; PIN stays)
```

**One-time codes (TOTP/HOTP)**
```sh
qk otp add github               # add a TOTP account; the base32 secret is prompted
    # --hotp [--counter N]  HOTP instead of TOTP
    # --digits 6|7|8  --algorithm SHA1|SHA256|SHA512
    # --touch               🔘 every code needs the button
qk otp list                     # accounts
qk otp code                     # all current codes
qk otp code github              # one code (HOTP and --touch accounts: computed on request)
qk otp delete github            # delete an account
qk otp set-password             # set, change or clear the OTP access password
```

**Challenge-response (KeePassXC)**
```sh
qk otp hmac set 2               # 🔘 slot 1 or 2, random 20-byte secret (--secret <hex> to set your own)
qk otp hmac status              # which slots are set
qk otp hmac delete 2            # 🔘 delete a slot
```

**Passwords**
```sh
qk pwd add github --login dev --url https://github.com --generate 24
    # --password <value> or prompted; --generate LEN creates it on the key
    # --chars luds  (l=lower u=upper d=digits s=symbols)
    # --note <text>  --otp <OTP account name>
    # --touch       🔘 reading or changing the record needs the button
qk pwd list                     # records without passwords
qk pwd get github --show        # record with the password (by name or ID)
qk pwd edit github --url https://github.com    # changes only the given fields
    # --name, --login, --note, --otp, --change-password (prompted),
    # --generate LEN, --touch / --no-touch
qk pwd delete github            # delete a record
qk pwd gen --length 20 --chars luds            # generate a password, not stored
qk pwd status                   # PIN state, number of records
qk pwd export backup.json       # all records to a file encrypted with a backup password
qk pwd import backup.json       # from a backup, or a Bitwarden/KeePassXC/Chrome/Firefox/
                                #   Safari/1Password CSV; records already on the key are skipped
qk pwd reset                    # 🔘 erase all passwords
```

**OpenPGP**
```sh
qk pgp status                   # serial, keys with algorithm, fingerprint and touch mode
qk pgp touch signature on       # 🔘 each use of the key needs the button; admin PIN
                                #   key: signature | decryption | authentication
                                #   mode: off | on | fixed ("fixed" is undone only by a reset)
qk pgp reset                    # erase OpenPGP keys and card data (admin PIN); PINs stay
```
Keys are created and used with `gpg --card-edit` (see "Compatibility").

**PIV**
```sh
qk piv status                   # slots 9A/9C/9D/9E and certificates
qk piv reset                    # 🔘 erase PIV keys and certificates; PINs stay
```
Keys and certificates are made with `ykman piv` or OpenSC.

Passkeys can also be viewed and deleted in Chrome: Settings → Privacy and
security → Security → Manage security keys.

PINs and passwords are prompted when omitted; options such as `--pin` are
visible to other processes and stay in the shell history — use them only in
scripts.

If the reader is busy (`Reader in use`), GnuPG's `scdaemon` holds it:
`gpgconf --kill scdaemon`.

## Compatibility

| Feature  | Tested with |
|----------|-------------|
| FIDO2/U2F | python-fido2 (registration, sign-in, PIN, credentialManagement, credProtect, hmac-secret, Ed25519, alwaysUv, largeBlobs) |
| SSH (FIDO) | OpenSSH 10.5: `ed25519-sk` regular and resident (`-O resident`), `ssh-keygen -K`, `-Y sign` signatures |
| CCID     | `opensc-tool -l`, `pcsc_scan` |
| OpenPGP  | gpg 2.2: `--card-status`, keytocard ed25519/cv25519, decryption, signing, SSH via gpg-agent; APDU tests |
| PIV      | `ykman piv`, `pkcs11-tool --module opensc-pkcs11.so -L` |
| OATH     | `ykman --reader "Quick-Key" oath ...`, `qk otp` |
| Challenge-response | KeePassXC over PC/SC (YubiKey protocol, slots 1/2); `test/device/touch_test.py` |
| Passwords | `qk pwd`, `test/device/pwd_test.py`; export/import (backup and browser CSV) — `test/host/qk_pwd_test.py` and manually on the key |

SSH via FIDO: the OpenSSH bundled with macOS does not support `-sk` keys; use
OpenSSH from Homebrew (`brew install openssh`).
```sh
ssh-keygen -t ed25519-sk                                    # button
ssh-keygen -t ed25519-sk -O resident -O application=ssh:qk  # PIN + button
ssh-keygen -K                                               # PIN: download resident keys
```
Resident keys with the same `application` and user overwrite each other (as
CTAP requires) — tell keys apart with `-O application=ssh:<name>`.

Button confirmation for OpenPGP and PIV keys (protects against malware using
the key after the PIN was entered):
```sh
qk pgp touch signature on      # decryption / authentication; off | on | fixed
                               # "fixed" can only be undone by `qk pgp reset`
                               # gpg 2.3+: gpg-card → uif 1 on (gpg 2.2 has no UIF command)
ykman --reader Quick-Key piv keys generate --touch-policy ALWAYS 9a pub.pem   # or CACHED (15 s)
```
PIV PIN policy is fixed per slot (9C — every use, 9E — never, others — once).

KeePassXC: `qk otp hmac set 2`, then in the database settings add a
"Challenge-Response" key and pick the Quick-Key slot. Slots answer without a
press and without the OTP password, like a YubiKey's; the same secret written
with `--secret` to a YubiKey or a second Quick-Key makes a backup key.

Defaults:
- Device PIN `123456` — one PIN for FIDO2, OpenPGP (PW1), PIV (PIN) and
  passwords; 6–8 characters of any kind, 8 retries.
- Admin PIN `12345678` — OpenPGP PW3 and PIV PUK; exactly 8 characters, 3 retries.
  Unblocks the PIN. If it is blocked too, only a full reset helps
  (`ykman piv reset` and gpg factory-reset lead to it as well, with the button).
- Both PINs must be changed before the key stores OpenPGP or PIV keys or
  passwords. 8 characters mixing letters, digits and symbols can't be
  guessed even by someone who gets code running on the chip; 6 digits can.
  PINs can't be longer than 8: PIV takes no more.
- PIV management key `010203040506070801020304050607080102030405060708` (3DES).

## Tests

```sh
make -C test/host               # CBOR, APDU, vault, shared PIN, Ed25519/X25519, passwords (needs ESP-IDF for mbedTLS)
python3 test/host/qk_pwd_test.py   # password export/import in qk, no key needed
```

Hardware tests are in [test/device](test/device/README.md).

## License

[MIT](LICENSE). Bundled [Monocypher](main/third_party/monocypher) is under
its own licence (BSD-2-Clause or CC0, see its `LICENCE.md`).
