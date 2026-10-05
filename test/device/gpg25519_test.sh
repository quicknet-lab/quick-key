#!/bin/sh
# End-to-end with real GnuPG: ed25519/cv25519/ed25519 key moved to the card with
# keytocard, then decrypt, sign and SSH-sign through the card. No button presses.
# Uses a throw-away GNUPGHOME (in /tmp: gpg-agent socket paths are length-limited)
# and resets the OpenPGP application before and after.
set -e
H=$(mktemp -d /tmp/qkgpg.XXXX)
export GNUPGHOME=$H
cleanup() { gpgconf --kill all; rm -rf "$H"; }
trap cleanup EXIT

cat > "$H/pinentry.sh" <<'EOF'
#!/bin/sh
# Test pinentry: Admin PIN 27182818, user PIN 314159.
echo "OK ready"
desc=""
while read -r cmd rest; do
  case "$cmd" in
    SETDESC) desc="$rest"; echo OK;;
    GETPIN) case "$desc" in *dmin*) echo "D 27182818";; *) echo "D 314159";; esac; echo OK;;
    BYE) echo OK; exit 0;;
    *) echo OK;;
  esac
done
EOF
chmod +x "$H/pinentry.sh"
printf 'pinentry-program %s\nenable-ssh-support\n' "$H/pinentry.sh" > "$H/gpg-agent.conf"
GNUPGHOME= gpgconf --kill scdaemon || true          # the user's scdaemon may hold the reader
QK="python3 $(dirname "$0")/../../tools/qk.py"
$QK pgp reset --admin-pin 27182818 >/dev/null                            # empty card: keytocard asks no "replace?" questions

gpg -q --batch --passphrase '' --quick-gen-key 'QK Test <qk@test.invalid>' ed25519 sign,cert 0
FPR=$(gpg --list-keys --with-colons | awk -F: '/^fpr/{print $10; exit}')
gpg -q --batch --passphrase '' --quick-add-key "$FPR" cv25519 encr 0
gpg -q --batch --passphrase '' --quick-add-key "$FPR" ed25519 auth 0
echo "secret for the card" > "$H/msg.txt"
gpg -q --batch --trust-model always -r "$FPR" -e -o "$H/msg.gpg" "$H/msg.txt"

printf 'keytocard\ny\n1\nkey 1\nkeytocard\n2\nkey 1\nkey 2\nkeytocard\n3\nsave\n' |
    gpg --batch --no-tty --command-fd 0 --edit-key "$FPR" >/dev/null 2>&1
gpg --card-status | grep -q "Key attributes ...: ed25519 cv25519 ed25519"
test "$(gpg -K | grep -cE '^(sec|ssb)>')" -eq 3
echo "keys moved to the card (ed25519 cv25519 ed25519)"

test "$(gpg -q --batch -d "$H/msg.gpg")" = "secret for the card"
echo "decrypted with the card's X25519 key"

echo "signed by the card" > "$H/s.txt"
gpg -q --batch --sign -o "$H/s.gpg" "$H/s.txt"
gpg -q --verify "$H/s.gpg" 2>&1 | grep -q "Good signature"
echo "Ed25519 signature verified"

export SSH_AUTH_SOCK=$(gpgconf --list-dirs agent-ssh-socket)
gpgconf --kill gpg-agent && gpgconf --launch gpg-agent && gpg --card-status >/dev/null
gpg --export-ssh-key "$FPR" > "$H/id.pub"
echo "ssh test" > "$H/t.txt"
ssh-keygen -q -Y sign -f "$H/id.pub" -n file "$H/t.txt" 2>/dev/null
echo "qk $(cat "$H/id.pub")" > "$H/allowed"
ssh-keygen -Y verify -f "$H/allowed" -I qk -n file -s "$H/t.txt.sig" < "$H/t.txt" >/dev/null
echo "SSH signature with the authentication key verified"

gpgconf --kill scdaemon
$QK pgp reset --admin-pin 27182818
echo "gpg 25519 tests passed"
