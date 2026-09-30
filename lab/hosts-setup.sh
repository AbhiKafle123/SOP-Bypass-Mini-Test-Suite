#!/usr/bin/env bash
# Map the lab hostnames to loopback.
#
# Real hostnames, not just ports, because two of the probe lanes need them:
# document.domain relaxation needs sibling subdomains of one registrable domain,
# and the origin-oracle lane needs a "documented" origin distinguishable from the
# origin content is actually loaded from. Neither is expressible with
# 127.0.0.1:PORT alone.
#
# .test is reserved by RFC 6761 for exactly this, so these names can never collide
# with a real registration and never leave the machine.
#
#   sudo bash lab/hosts-setup.sh          # add entries
#   sudo bash lab/hosts-setup.sh --remove # take them back out
set -euo pipefail

HOSTS=/etc/hosts
MARK_BEGIN='# --- SOP Bypass Mini Test Suite: cross-origin lab topology ---'
MARK_END='# --- end SOP lab ---'

NAMES=(
  victim.sop-lab.test
  sub.victim.sop-lab.test
  attacker.sop-lab.test
  sop-lab.test
  documented.sop-lab.test
)

if [ "${1:-}" = "--remove" ]; then
  if grep -qF "$MARK_BEGIN" "$HOSTS"; then
    # Delete the marked block, inclusive.
    sed -i "/$(printf '%s' "$MARK_BEGIN" | sed 's/[][\.*^$/]/\\&/g')/,/$(printf '%s' "$MARK_END" | sed 's/[][\.*^$/]/\\&/g')/d" "$HOSTS"
    echo "removed lab entries from $HOSTS"
  else
    echo "no lab entries found in $HOSTS"
  fi
  exit 0
fi

if [ "$(id -u)" != "0" ]; then
  echo "need root to write $HOSTS — re-run with sudo" >&2
  exit 1
fi

if grep -qF "$MARK_BEGIN" "$HOSTS"; then
  echo "lab entries already present in $HOSTS"
else
  {
    echo ""
    echo "$MARK_BEGIN"
    for n in "${NAMES[@]}"; do echo "127.0.0.1 $n"; done
    echo "$MARK_END"
  } >> "$HOSTS"
  echo "added ${#NAMES[@]} entries to $HOSTS"
fi

echo "verifying resolution:"
fail=0
for n in "${NAMES[@]}"; do
  if getent hosts "$n" >/dev/null 2>&1; then
    printf '  ok      %s\n' "$n"
  else
    printf '  FAILED  %s\n' "$n"; fail=1
  fi
done
exit $fail
