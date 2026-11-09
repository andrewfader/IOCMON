#!/bin/sh
# Alert emails must survive a mail provider that rejects flagged hostnames, and an outage must not lose them.
# The mailer is a stub, so nothing is sent.
# Usage: tests/test_alert_email_delivery.sh [path/to/iocmon.sh]
S="${1:-iocmon.sh}"; T="${TMPDIR:-/tmp}/pr-test.$$"; mkdir -p "$T/state" || exit 1; trap 'rm -rf "$T"' EXIT; rc=0
ext() { awk -v n="$1" '$0==n"()"{f=1} f{print} f&&/^}/{exit}' "$S"; }
for f in emaildefang emailshownindicator emailrow emaillinkrow emaildivider emailsection emailfamilyrows emailfeedname isfeedmatchsource abusechemaillinks emailalertbody ratelimiter sendmessage sendbatchmessage queueemailalert flushemailbatch _SendEMailNotification_; do ext "$f"; done > "$T/f.sh"
grep -m1 '^emailfallbacksubject=' "$S" >> "$T/f.sh"
. "$T/f.sh"
sleep() { :; }; loadcemlibrary() { :; }; resolvestateroot() { :; }; _GetLAN_HostName_() { echo r; }
amtmIsEMailConfigFileEnabled=1; enablealertemail=1; ratelimit=0; version=t; emailwrapwidth=78; scriptFileNTag=t
addonsdir="$T"; logfile="$T/log"; stateroot="$T/state"; mkdir -p /tmp/var/tmp
P="$stateroot/email_batch.pending"; R="$stateroot/email_batch.retry"; M="$T/mail"
# Stub: MODE=ok sends, MODE=down always fails, MODE=reject fails if $FLAG shows outside a link.
_SendEMailNotification_CEM_() {
  b="${2#-F=}"; { printf 'SUBJ %s\n' "$1"; cat "$b"; echo "=END"; } >> "$M"
  case "$MODE" in
    down) return 7 ;;
    reject) { printf '%s\n' "$1"; sed 's/<a href[^>]*>[^<]*<\/a>//' "$b"; } | grep -qF "$FLAG" && return 55 ;;
  esac
  return 0
}
new() { MODE="$1"; FLAG="$2"; rm -f "$P" "$R" "$stateroot"/email_batch.*; : > "$M"; : > "$logfile"; }
sends() { grep -c '^SUBJ' "$M"; }
ok() { if eval "$2"; then echo "PASS $1"; else echo "FAIL $1"; rc=1; fi; }
run() { flushemailbatch >/dev/null 2>&1; }

new reject analogbard.com; queueemailalert dns '192.168.50.1->analogbard.com' urlhaus 'malware_download; 1 URL(s)' - ''; run
ok "flagged domain is accepted, in one email" '[ "$(sends)" = 1 ] && ! grep -qF "Failure to send" "$logfile"'
ok "subject shows it defanged" 'grep -qF "(192.168.50.1->analogbard[.]com)" "$M"'
ok "link keeps the real host" 'grep -qF "urlhaus.abuse.ch/host/analogbard.com/" "$M"'

new ok ''; queueemailalert fsintegrity /jffs/scripts/iocmon.sh new-executable d - ''; run
ok "file paths are not defanged" 'grep -qF "/jffs/scripts/iocmon.sh" "$M" && ! grep -qF "iocmon[.]sh" "$M"'

new reject SECRETFLAG; queueemailalert dns '192.168.50.1->x.example' netapi 'family SECRETFLAG' - ''; run
ok "rejected alert sends a second notice" '[ "$(sends)" = 2 ]'
ok "notice has no indicators" '! sed -n "/^=END/,\$p" "$M" | grep -qE "x\.example|SECRETFLAG"'
ok "rejected alert is not retried forever" '[ ! -s "$P" ]'

new down ''; queueemailalert conntrack '192.168.50.49->9.9.9.9' urlhaus d - ''; run
ok "outage keeps the alert" '[ -s "$P" ]'
ok "outage sets a retry time" '[ -s "$R" ]'
: > "$M"; run
ok "no resend during the backoff" '[ "$(sends)" = 0 ]'
MODE=ok; echo "1 0" > "$R"; run
ok "resent after the backoff, state cleared" '[ "$(sends)" = 1 ] && [ ! -s "$P" ] && [ ! -e "$R" ]'

new down ''; queueemailalert conntrack 'a->9.9.9.9' urlhaus d - ''; echo "5 0" > "$R"; run
ok "gives up after 6 attempts and logs it" '[ ! -s "$P" ] && grep -qF "Gave up emailing" "$logfile"'

new down ''; sendmessage 1 test "Test alert" manual x >/dev/null 2>&1
ok "failed test email sends no notice" '[ "$(sends)" = 1 ]'
# A missing email library doesn't count as a sent email.
awk '$0=="_SendEMailNotification_()"{f=1} f{print} f&&/^}/{exit}' "$S" > send.sh; . ./send.sh
_DownloadCEMLibraryFile_() { :; }; sleep() { :; }; amtmIsEMailConfigFileEnabled=; CUSTOM_EMAIL_LIBFile=./missing; emailsendrc=0; logfile=run.log
_SendEMailNotification_ a b c > /dev/null 2>&1
if [ "$emailsendrc" != 0 ]; then echo "PASS missing library isn't a sent email"; else echo "FAIL missing library isn't a sent email"; rc=1; fi
unset -f sleep

exit $rc
