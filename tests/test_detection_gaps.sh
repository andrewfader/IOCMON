#!/bin/sh
# Runs the login, baseline and file change checks from iocmon.sh on sample data.
# Usage: tests/test_detection_gaps.sh [path/to/iocmon.sh]
S="$(cd "$(dirname "${1:-iocmon.sh}")" && pwd)/$(basename "${1:-iocmon.sh}")"
T="${TMPDIR:-/tmp}/pr-test.$$"; mkdir -p "$T" || exit 1; trap 'rm -rf "$T"' EXIT; rc=0; cd "$T" || exit 1
ok() { echo "PASS $1"; }; no() { echo "FAIL $1"; rc=1; }
check() { if eval "$2"; then ok "$1"; else no "$1"; fi; }
fn() { awk -v n="$1()" '$0==n{f=1} f{print} f&&/^}/{exit}' "$S"; }

# With no external drive, the install root must not exclude every path.
eval "$(fn fspathexcluded)"; addonsdir=/jffs/addons/iocmon.d; CUSTOM_EMAIL_LIBDir=/jffs/addons/shared; fsexclude=
iocmonroot=; check "empty root excludes nothing" "! fspathexcluded /jffs/scripts/firewall-start"
iocmonroot=/tmp/mnt/usb/iocmon.d; check "root still excluded" "fspathexcluded /tmp/mnt/usb/iocmon.d/x"

# Real failed web logins and SSH logins for unknown users are counted.
cat > log <<'L'
Nov  8 04:00:00 HTTPD: [LOGIN][https][Web] failed (192.168.50.9)
Nov  8 04:00:01 dropbear[12]: Login attempt for nonexistent user from 192.168.50.8:5000
Nov  8 04:00:02 dropbear[12]: Bad password attempt for 'admin' from 192.168.50.7:5000
Nov  8 04:00:03 dnsmasq[1]: query[A] httpd login fail 8.8.8.8 from 192.168.50.6
L
synclog=log; authnewlines() { cat; }; httpdseenfile=x; dropbearseenfile=x
grep -F 'httpdlines="$(' "$S" | head -n 1 > h.sh; grep -F 'dropbearlines="$(' "$S" | head -n 1 > d.sh; . ./h.sh; . ./d.sh
check "failed web login counted" "echo \"\$httpdlines\" | grep -q 192.168.50.9"
check "DNS query can't fake a web login" "! echo \"\$httpdlines\" | grep -q 8.8.8.8"
check "unknown SSH user counted" "echo \"\$dropbearlines\" | grep -q 192.168.50.8"
check "wrong SSH password counted" "echo \"\$dropbearlines\" | grep -q 192.168.50.7"

# An empty baseline is a baseline, so the first new rule is seen.
: > oldtab; echo rule > newtab; oldtab=oldtab; newtab=newtab
{ echo 'base() {'; grep -F 'if [ ! ' "$S" | grep -F '"$oldtab" ]; then' | head -n 1; echo 'mv "$newtab" "$oldtab"; return; fi; echo COMPARE; }'; } > base.sh; . ./base.sh
check "empty baseline still compares" "[ \"\$(base)\" = COMPARE ]"
rm -f oldtab; check "missing baseline is first run" "[ -z \"\$(base)\" ] && [ -s oldtab ]"

# In hash mode a file's first change is reported.
{ echo 'tail1() {'; grep -F '[ -z "$oldhash" ] && return' "$S" | head -n 1; echo '[ "$oldhash" != "$newhash" ]; }'; } > hash.sh; . ./hash.sh
oldhash=; newhash=abc; check "first hash change is reported" "tail1"
oldhash=abc; check "same hash stays quiet" "! tail1"; newhash=abd; check "new hash is reported" "tail1"

# The router's own reverse lookups aren't DNS tunnels.
eval "$(fn dnstunnelscan)"; dnstunnelnamelen=10
{ echo '1.1.168.192.in-addr.arpa|127.0.0.1'; echo 'longname.example.com|192.168.50.2'; } | dnstunnelscan > scan.out
check "reverse lookups ignored" "! grep -q arpa scan.out"
check "normal names still scanned" "grep -q example.com scan.out"

exit $rc
