#!/bin/sh
# The family child: a parent that declares one initial child (tiny) in
# initial_environment_workload, and starts it once at boot.
#
# The node funds this instance with what it quoted for it: the start of the
# service plus EstimatedCost.children_initial_cost (nodo #538). So the one start
# of tiny has to succeed at the first attempt: `--attempts 1`, no retry loop.
# The verifier reads the result at /status.txt and stops the child through
# /cgi-bin/stop before it stops this instance.
W=/www
mkdir -p "$W/cgi-bin" /tmp/celaut
cp /service/stop.cgi "$W/cgi-bin/stop"
chmod 755 "$W/cgi-bin/stop"
echo "state=starting" > "$W/status.txt"
# Serve at once (busybox httpd goes to the background), so the node's readiness
# and the verifier do not wait for the start of the child.
httpd -p 8080 -h "$W"
t0=$(date +%s)
# tiny is carried under /service (pack_config.json): the node is sent it if it
# does not hold it.
celaut acquire --new --attempts 1 --name TINY --root /service \
    > "$W/acquire.json" 2> "$W/acquire.err"
rc=$?
tiny=$(sed -n 's/^TINY=//p' /service/.dependencies)
printf 'state=done\nrc=%s\nattempts=1\nseconds=%s\ntiny=%s\n' \
    "$rc" "$(( $(date +%s) - t0 ))" "$tiny" > "$W/status.txt"
while :; do sleep 3600; done
