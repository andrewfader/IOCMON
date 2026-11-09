#!/bin/sh
# Runs the DNS watch and feed code from iocmon.sh on sample data.
# Usage: tests/test_dns_feed_bugs.sh [path/to/iocmon.sh]
S="$(cd "$(dirname "${1:-iocmon.sh}")" && pwd)/$(basename "${1:-iocmon.sh}")"
T="${TMPDIR:-/tmp}/pr-test.$$"; mkdir -p "$T" || exit 1; trap 'rm -rf "$T" "/tmp/iocmon_dns_range.$$"' EXIT; rc=0; cd "$T" || exit 1
ok() { echo "PASS $1"; }; no() { echo "FAIL $1"; rc=1; }
check() { if eval "$2"; then ok "$1"; else no "$1"; fi; }
fn() { awk -v n="$1()" '$0==n{f=1} f{print} f&&/^}/{exit}' "$S"; }
_GetLAN_HostName_() { echo host; }; inlinestatus() { :; }; dedupindicators() { :; }

# Lines arriving after the count must wait for the next tick, and none may be skipped.
i=1; while [ "$i" -le 7 ]; do echo "Nov  8 00:00:0$i dnsmasq[1]: query[A] a$i.example.com from 192.168.50.2"; i=$((i + 1)); done > log
{ echo 'range() {'; awk '$0=="checkdns()"{f=1} f&&/^ *newlines=\$\(\(linecount - lastcount\)\)$/{p=1} p{print} p&&/\| sort -u\)"$/{exit}' "$S"
  echo 'printf "%s\n" "$querypairs"; }'; } > range.sh
( . ./range.sh; synclog=log; lastcount=2; linecount=5; range ) > range.out 2>&1
check "counted lines are read" "grep -q '^a3.example.com|' range.out && grep -q '^a5.example.com|' range.out"
check "lines after the count wait" "! grep -q '^a7.example.com|' range.out"

# After a log rotation, lines left in the old file are read as well.
sed -n 1,3p log > rotated-1; ln -s rotated-1 "log2-1" 2>/dev/null; sed -n 4,5p log > log2
( . ./range.sh; synclog=log2; lastcount=0; linecount=2; anchor=$(sed -n 1p log); range ) > rot.out 2>&1
check "lines before a rotation are read" "grep -q '^a2.example.com|' rot.out && grep -q '^a4.example.com|' rot.out"

# A flood of long names from one source raises at most three alerts.
eval "$(fn dnstunnelscan)"; dnstunnelnamelen=10
i=1; while [ "$i" -le 6 ]; do echo "longname$i.example.com|192.168.50.2"; i=$((i + 1)); done > long
dnstunnelscan < long > long.out
check "long-name alerts are capped" "[ \"\$(grep -c '^LONG' long.out)\" = 3 ]"
check "volume still counts every query" "grep -q '^VOL|192.168.50.2|example.com|6$' long.out"

# A query for a subdomain of a feed domain is credited to the feed.
sed -n '/^  awk -F.|. -v pf="\$dnspairfile" -v qf="\$qfdomfile" .$/,/^  . "\$@" | while/p' "$S" | sed '1d;$d' > match.awk
echo 'sub.evil.example|192.168.50.2' > pairs; echo 'evil.example|somefeed|family' > domains
awk -F'|' -v pf=pairs -v qf= -f match.awk pairs domains > match.out 2>&1
check "feed credited on parent domain" "grep -q '^192.168.50.2|evil.example|somefeed|family$' match.out"

# ThreatFox domains are lower-cased; hashes keep their case.
awk '/inlinestatus "Normalizing ThreatFox"/{f=1} f&&/-v ipsout=/{p=1;next} p&&/END \{ print skip\+0 \}/{exit} p{print}' "$S" > tf.awk
printf 'EVIL.Example.COM\tdomain\tm\t\t\t\nABCDEF\tmd5_hash\tm\t\t\t\n' | awk -F'\t' -v ipsout=i.out -v domainsout=d.out -v hashesout=h.out -f tf.awk > /dev/null 2>&1
check "ThreatFox domain lower-cased" "grep -q '^evil.example.com|threatfox|' d.out"
check "ThreatFox hash keeps its case" "grep -q '^ABCDEF|threatfox|' h.out"

# An empty run keeps the previous domains while a feed is enabled, and clears them otherwise.
awk '/^  if \[ -s "\$tmpdomains" \]; then$/{p=1} p{print} p&&/^  fi$/{exit}' "$S" > norm.sh
mkdir feeds; feedsroot=feeds; tmpdomains=missing; logfile=norm.log
echo 'old.example|x|y' > feeds/domains.txt; enablethreatfox=1; . ./norm.sh
check "empty run keeps previous domains" "grep -q old.example feeds/domains.txt"
enablethreatfox=0; enableurlhaus=0; enablenetapi=0; . ./norm.sh
check "disabled feeds clear domains" "[ ! -s feeds/domains.txt ]"

# Expired cooldown entries are pruned.
grep -F "awk -F'\t' -v k=\"\$key\"" "$S" | grep -F '"${dbfile}.tmp"' | head -n 1 > cool.sh
printf 'stale\t100\nfresh\t950\n' > db; dbfile=db; key=new; nowepoch=1000; cooldownsec=100; . ./cool.sh
check "expired entry pruned" "! grep -q '^stale' db.tmp"
check "live entries kept" "grep -q '^fresh' db.tmp && grep -q '^new' db.tmp"

# Auto-update moves only to a newer version.
eval "$(fn vercompare)"
{ grep -F 'if [ -n "$remoteversion" ] && [ ' "$S" | head -n 1; echo 'echo UPDATE; fi'; } > upd.sh
version=2.0.4; remoteversion=2.0.3; check "older version is not installed" "[ -z \"\$(. ./upd.sh 2>/dev/null)\" ]"
remoteversion=2.0.5; check "newer version is installed" "[ \"\$(. ./upd.sh 2>/dev/null)\" = UPDATE ]"

sh -n "$S" && ok syntax || no syntax
exit $rc
