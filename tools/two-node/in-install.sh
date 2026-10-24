#!/bin/bash
# in-install.sh : clean root install of celaut-project/nodo dev inside a test container.
# Log: /root/install.log
exec > /root/install.log 2>&1
URL=https://github.com/celaut-project/nodo.git
BR=dev
WANT="${WANT:-97906c7c}"
t=$(date +%s)
rm -rf /root/src && git clone -q --branch "$BR" --single-branch "$URL" /root/src
git -C /root/src log --oneline -1
[ "$(git -C /root/src rev-parse --short=8 HEAD)" = "$WANT" ] || { echo "dev moved: $(git -C /root/src rev-parse HEAD) != $WANT"; exit 3; }
cd /root/src
./install.sh --repo-url "$URL" --branch "$BR" < /dev/null
echo "INSTALL_RC=$? in $(( $(date +%s) - t ))s"
git -c safe.directory='*' -C /nodo log --oneline -1
systemctl is-active nodo.service
echo INSTALL_DONE
