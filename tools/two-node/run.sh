#!/bin/bash
# run.sh <step> : the two-node benchmark of delegation_pricing (nodo #577/#586) and of
# MAINTENANCE_OVERCHARGED (#567), on one x86_64 Linux host with systemd-nspawn and KVM.
#
# Node A (container nta) runs the verifier and delegates its child to node B (ntb). No
# ledger is used: B credits A's client with free MU (nodo credit_client), the wallets of
# both nodes are new and empty, and AUTOMATIC_REFILL stays off. See README.md.
#
# Steps, in order:
#   up            make both containers and install nodo dev in each (~16 min)
#   configure     A: host_limits so that only the verifier fits (its child must go to a
#                 peer); B: half of A's prices; peer A -> B; B credits A's client
#   verifier BEE  import the verifier export BEE on A, execute it, top it up
#   build-child ID  run the child once on B so that B has built it (see the step)
#   probe [label] call /probe/delegation_pricing on A's verifier, save the JSON
#   overcharge    patch B to charge 5x its quote on every maintenance tick, restart B
#   score         A's reputation events and statement faults against B
#   down          stop the instances and remove both containers
set -u
D=$(cd "$(dirname "$0")" && pwd)
OUT=${OUT:-$D/out}
mkdir -p "$OUT"
A=nta; B=ntb
in_ct() { local ct=$1; shift; systemd-run -M "$ct" --wait -q -P -p TimeoutStartSec=3600 bash -c "$*"; }

verifier_uri() {
  in_ct $A "nodo instances --json" | python3 -c '
import json, re, sys
d = json.load(sys.stdin)
for i in (d if isinstance(d, list) else d.get("instances", [])):
    if i.get("name") == "bench-two":
        m = re.search(r"(\d+\.\d+\.\d+\.\d+):5000", json.dumps(i))
        print(m.group(1) + ":5000" if m else ""); break'
}

case "${1:?step}" in
up)
  bash "$D/ct.sh" base
  CT=$A NETN=101 bash "$D/ct.sh" up
  CT=$B NETN=102 bash "$D/ct.sh" up
  for ct in $A $B; do
    cp "$D/in-install.sh" "/var/lib/machines/$ct/root/"
    systemd-run -M $ct --unit=demo-install --collect -p TimeoutStartSec=3600 bash /root/in-install.sh
  done
  timeout 3000 bash -c "until grep -q INSTALL_DONE /var/lib/machines/$A/root/install.log \
    && grep -q INSTALL_DONE /var/lib/machines/$B/root/install.log; do sleep 15; done"
  grep -h INSTALL_RC /var/lib/machines/$A/root/install.log /var/lib/machines/$B/root/install.log
  ;;
configure)
  # Room for the verifier alone (its 2.0e9 B of memory, and 20 MB more): A has no room
  # for its child, so it asks its peers, and B runs it. A CPU share does not do it: an
  # instance that declares no CPU quota is not counted against it.
  SHARE=$(python3 -c 'import os; print(round(2.02e9 / (os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES")), 5))')
  in_ct $A "nodo config set host_limits.ENABLED=true && nodo config set host_limits.MAX_CPU_SHARE=0 && nodo config set host_limits.MAX_RAM_SHARE=$SHARE"
  # A third of A's prices. A delegates only to a peer that its own price covers, at the
  # start and per second at the start and at the most (delegated_price.covers), and B's
  # most is its price at the worst multiplier of its MAX_PRICE_VOLATILITY (2.0): half of
  # A's prices would tie. A node that passed B's price on to its client would show a
  # third of its own rates.
  in_ct $B "nodo config set pricing.CPU_MU_PER_VCPU_HOUR=1333333 && nodo config set pricing.RAM_MU_PER_GIB_HOUR=333333 && nodo config set pricing.DISK_MU_PER_GIB_HOUR=33333"
  BADDR=$(in_ct $B "nodo status" | sed -n 's/^Address: *\([0-9.]*:[0-9]*\).*/\1/p')
  in_ct $A "nodo connect $BADDR"
  CLIENT=$(in_ct $A "nodo peers" | sed -n 's/^ *Remote Client ID: *//p' | head -1)
  in_ct $B "nodo credit_client $CLIENT 2000000000"
  ;;
build-child)
  # A covers B only when B's build is not above A's own (delegated_price.covers compares
  # the builds): a node that has built the child itself never delegates it to a peer
  # that has not. B runs the child once to build it, and stops it.
  CHILD=${2:?service id of the child}
  in_ct $B "timeout 600 nodo execute --name build-child $CHILD < /dev/null > /root/build-child.log 2>&1; for i in \$(nodo instances --json | python3 -c 'import json, sys; d = json.load(sys.stdin); print(\" \".join(i[\"id\"] for i in (d if isinstance(d, list) else d.get(\"instances\", []))))'); do nodo kill \$i; done"
  ;;
verifier)
  BEE=${2:?verifier export .bee}
  mkdir -p /var/tmp/demo-bee && cp "$BEE" /var/tmp/demo-bee/verifier.bee
  # /var/tmp/demo-bee is bound read-only at /var/tmp/bee in each container (ct.sh).
  in_ct $A "nodo import /var/tmp/bee/verifier.bee"
  SID=$(in_ct $A "nodo services" | awk '/celaut-node-honesty-verifier/ {print $1; exit}')
  # STARTUP_MAX_ATTEMPTS 0: no startup suite on A. A has room for the verifier alone,
  # so every child would be delegated, and the suite would hold the lock that the
  # single probe needs.
  in_ct $A "timeout 1500 nodo execute --name bench-two -e STARTUP_MAX_ATTEMPTS 0 $SID < /dev/null > /root/exec.log 2>&1; tail -3 /root/exec.log"
  TOKEN=$(in_ct $A "nodo instances --json" | python3 -c '
import json, sys
d = json.load(sys.stdin)
print([i["id"] for i in (d if isinstance(d, list) else d.get("instances", [])) if i.get("name") == "bench-two"][0])')
  in_ct $A "nodo increase_deposit $TOKEN 200000000"
  ;;
probe)
  LABEL=${2:-honest}
  URI=$(verifier_uri)
  # The node reports the instance before its HTTP server listens.
  in_ct $A "timeout 180 bash -c 'until curl -s -m 5 -o /dev/null http://$URI/status; do sleep 5; done'"
  in_ct $A "curl -s --max-time 900 -X POST http://$URI/probe/delegation_pricing" > "$OUT/delegation-$LABEL.json"
  python3 -c "import json; d=json.load(open('$OUT/delegation-$LABEL.json')); print(d['verdict'], '-', d['reason'])"
  ;;
overcharge)
  # A dishonest peer, on purpose: B's maintenance tick charges five times the price, and
  # its quotes stay as they were (a quote prices with no launch_bp; the tick passes the
  # one of the instance). Test-only.
  cp "$D/overcharge.py" "/var/lib/machines/$B/root/overcharge.py"
  in_ct $B "cd /nodo && python3 /root/overcharge.py && git -C /nodo diff --stat && systemctl restart nodo && sleep 10 && systemctl is-active nodo"
  ;;
score)
  BID=$(in_ct $B "nodo status" | sed -n 's/^Node id: *//p')
  in_ct $A "python3 - <<EOF
import sqlite3
c = sqlite3.connect('file:/nodo/storage/database.sqlite?mode=ro', uri=True)
print('reputation_events:', c.execute(\"SELECT reason, amount, score_after, created_at FROM reputation_events WHERE subject_id = '$BID'\").fetchall())
print('statement_faults:', c.execute(\"SELECT reason, seq, period, ts FROM statement_faults WHERE peer_id = '$BID'\").fetchall())
EOF" | tee "$OUT/score.txt"
  ;;
down)
  for ct in $A $B; do
    in_ct $ct "for i in \$(nodo instances --json | python3 -c 'import json,sys; d=json.load(sys.stdin); print(\" \".join(i[\"id\"] for i in (d if isinstance(d, list) else d.get(\"instances\", []))))'); do nodo kill \$i; done" 2>/dev/null
  done
  CT=$A NETN=101 bash "$D/ct.sh" down
  CT=$B NETN=102 bash "$D/ct.sh" down
  ;;
*)
  echo "unknown step: $1"; exit 2 ;;
esac
