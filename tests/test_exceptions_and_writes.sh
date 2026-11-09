#!/bin/sh
# Runs the Skynet import filter, NVRAM baseline, config save and AdGuard filter from iocmon.sh.
# Usage: tests/test_exceptions_and_writes.sh [path/to/iocmon.sh]
S="$(cd "$(dirname "${1:-iocmon.sh}")" && pwd)/$(basename "${1:-iocmon.sh}")"
T="${TMPDIR:-/tmp}/pr-test.$$"; mkdir -p "$T" || exit 1; trap 'rm -rf "$T"' EXIT; rc=0; cd "$T" || exit 1
ok() { echo "PASS $1"; }; no() { echo "FAIL $1"; rc=1; }
check() { if eval "$2"; then ok "$1"; else no "$1"; fi; }
fn() { awk -v n="$1()" '$0==n{f=1} f{print} f&&/^}/{exit}' "$S"; }

# An exception is cut out of a feed range; the rest of the range stays.
eval "$(fn buildskynetimportfile)"; skynetprogress() { :; }; feedsroot=.; skynetimportqfeeds=0
cat > ips.txt <<'L'
1.2.3.0/24|a
5.5.5.5|a
7.7.0.0/16|a
8.8.8.8|a
9.9.9.0/24|a
200.1.2.0/30|a
L
ipexceptions="1.2.3.4 5.5.5.5 7.0.0.0/8 9.9.9.0/25 200.1.2.1 200.1.2.2"
buildskynetimportfile out
sort out > got
cat > want.unsorted <<'L'
1.2.3.0/30
1.2.3.5
1.2.3.6/31
1.2.3.8/29
1.2.3.16/28
1.2.3.32/27
1.2.3.64/26
1.2.3.128/25
8.8.8.8
9.9.9.128/25
200.1.2.0
200.1.2.3
L
sort want.unsorted > want
check "ranges are split around exceptions" "cmp -s got want"
check "plain exception is removed" "! grep -q '^5.5.5.5$' got"
check "range inside a wider exception is removed" "! grep -q '^7\.' got"
check "untouched address is kept" "grep -q '^8.8.8.8$' got"
ipexceptions=""; buildskynetimportfile out
check "no exceptions leaves the list alone" "[ \"\$(wc -l < out | tr -d ' ')\" = 6 ]"
ipexceptions="1.2.3.0/24"; buildskynetimportfile out
check "identical exception removes the range" "! grep -q '^1.2.3.0/24$' out"

# The baseline is written only when a value changes, and alerts still say when it was last checked.
eval "$(fn checknvram)"; resolvestateroot() { stateroot=.; }; aghlog() { :; }
enablenvramwatch=1; nvramwatchvars="alpha beta"; nvramval=one
nvramget() { nvramval="$nvramnow"; }
raisealert() { echo "$4" > alert; }; date() { echo "$fakedate"; }
nvramnow=one; fakedate=first; checknvram; cp nvram_baseline.db b1
fakedate=second; checknvram
check "unchanged values leave the baseline alone" "cmp -s b1 nvram_baseline.db"
check "no alert without a change" "[ ! -e alert ]"
fakedate=third; nvramnow=two; checknvram
check "a change is alerted" "grep -q \"changed from 'one' to 'two'\" alert"
check "alert names the last check, not the last change" "grep -q 'last recorded second' alert"
check "a change updates the baseline" "grep -q '^alpha=two$' nvram_baseline.db"
check "no temp file is left" "[ -z \"\$(ls /tmp/iocmon_nvram_baseline.\$\$ 2>/dev/null)\" ]"
unset -f date

# The saved config stays whole until the new one is complete.
eval "$(fn saveconfig)"
migratealertlevel() { :; }; resolvelogfile() { :; }; schedulecron() { :; }; autostart() { :; }; syncwebui() { :; }; _GetLAN_HostName_() { echo host; }
config=cfg; logfile=log; echo 'timerloop=OLD' > cfg
echo() { [ -s cfg ] || : > truncated; printf '%s\n' "$*"; }
( saveconfig ) > /dev/null 2>&1
unset -f echo
check "config isn't truncated during a save" "[ ! -e truncated ]"
check "save completes" "grep -q '^enablewebui=' cfg"
check "no new file is left" "[ ! -e cfg.new ]"

# AdGuard Home fields that aren't a name, address and number don't get through.
grep -F 'sed 1d "$tmp/page"' "$S" | head -n 1 > agh.sh; tmp=.; : > all
cat > page <<'L'
M|2|0|1|x
Q|good.example.com|192.168.50.2|1762570000|0
R|good.example.com|93.184.216.34
Q|bad$(touch PWN).example.com|192.168.50.2|1762570000|0
Q|bad|name.example.com|192.168.50.2|1762570000|0
R|good.example.com|`touch PWN`
L
. ./agh.sh
check "good lines pass" "[ \"\$(grep -c good all)\" = 2 ]"
check "bad names are dropped" "! grep -q bad all"
check "bad answers are dropped" "! grep -q PWN all"

exit $rc
