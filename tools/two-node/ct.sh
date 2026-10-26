#!/bin/bash
# ct.sh up|down|status : an isolated systemd-nspawn container for one test nodo on the
# WSL host (demo-service two-node benchmarks). Own netns (veth ve-<name>, 10.213.<N>.0/30),
# own iptables chains, /dev/kvm bound in. Nothing of the main /nodo is read or changed.
set -u
# CT=<name> NETN=<third octet> pick the container (run.sh uses nta/101 and ntb/102).
N=${CT:-ntx}; R=/var/lib/machines/$N; BASE=/var/lib/machines/ntbase
O3=${NETN:-99}; HIP=10.213.$O3.1; CIP=10.213.$O3.2; NET=10.213.$O3.0/30; VE=ve-$N
C=$(echo "$N" | tr a-z A-Z); FWD=${C}_FWD; NAT=${C}_NAT
case "${1:?base|up|down|status}" in
base)
  # The template every container is copied from: Ubuntu 22.04 minbase with what
  # nodo's install.sh needs before it installs the rest itself.
  [ -e "$BASE" ] && { echo "$BASE exists"; exit 0; }
  debootstrap --variant=minbase --components=main,universe jammy "$BASE" http://archive.ubuntu.com/ubuntu
  printf 'deb http://archive.ubuntu.com/ubuntu jammy main universe\ndeb http://archive.ubuntu.com/ubuntu jammy-updates main universe\ndeb http://security.ubuntu.com/ubuntu jammy-security main universe\n' > "$BASE/etc/apt/sources.list"
  chroot "$BASE" bash -c 'apt-get update -q && DEBIAN_FRONTEND=noninteractive apt-get install -y -q systemd systemd-sysv dbus git curl ca-certificates sudo iproute2 iputils-ping python3 locales'
  ;;
up)
  [ -e "$R" ] && { echo "$R exists"; exit 1; }
  ip -4 route | grep -q "^${NET%/*}" && { echo "$NET routed"; exit 1; }
  cp -a "$BASE" "$R"
  # kvm group with the host gid of /dev/kvm, so the bound node is root:kvm 0660 inside too
  kg=$(stat -c %g /dev/kvm)
  if chroot "$R" getent group kvm >/dev/null; then chroot "$R" groupmod -g "$kg" kvm; else chroot "$R" groupadd -g "$kg" kvm; fi
  mkdir -p "$R/etc/systemd/network"
  printf '[Match]\nName=host0\n[Network]\nAddress=%s/30\nGateway=%s\n' "$CIP" "$HIP" > "$R/etc/systemd/network/10-host0.network"
  ln -sf /lib/systemd/system/systemd-networkd.service "$R/etc/systemd/system/multi-user.target.wants/systemd-networkd.service"
  rm -f "$R/etc/resolv.conf"; printf 'nameserver 1.1.1.1\nnameserver 8.8.8.8\n' > "$R/etc/resolv.conf"
  echo $N > "$R/etc/hostname"
  mkdir -p /etc/systemd/nspawn "/etc/systemd/system/systemd-nspawn@$N.service.d"
  cat > /etc/systemd/nspawn/$N.nspawn <<EOF
[Exec]
Boot=yes
PrivateUsers=no
ResolvConf=off
[Files]
Bind=/dev/kvm
BindReadOnly=/var/tmp/demo-bee:/var/tmp/bee
[Network]
VirtualEthernet=yes
EOF
  printf '[Service]\nDeviceAllow=/dev/kvm rw\n' > "/etc/systemd/system/systemd-nspawn@$N.service.d/kvm.conf"
  systemctl daemon-reload
  systemctl start "systemd-nspawn@$N.service"
  for i in $(seq 1 30); do ip link show "$VE" >/dev/null 2>&1 && break; sleep 1; done
  ip addr add "$HIP/30" dev "$VE"; ip link set "$VE" up
  if ! iptables -S $FWD >/dev/null 2>&1; then
    iptables -N $FWD
    iptables -A $FWD -i "$VE" -m comment --comment $N -j ACCEPT
    iptables -A $FWD -o "$VE" -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment $N -j ACCEPT
    iptables -I FORWARD 1 -m comment --comment $N -j $FWD
    iptables -t nat -N $NAT
    iptables -t nat -A $NAT -s "$NET" ! -o "$VE" -m comment --comment $N -j MASQUERADE
    iptables -t nat -I POSTROUTING 1 -m comment --comment $N -j $NAT
  fi
  for i in $(seq 1 30); do systemd-run -M $N --wait -q -P true 2>/dev/null && break; sleep 1; done
  echo "up: $(machinectl list --no-legend | grep $N)"
  ;;
down)
  machinectl poweroff "$N" 2>/dev/null
  for i in $(seq 1 30); do systemctl is-active -q "systemd-nspawn@$N.service" || break; sleep 1; done
  systemctl stop "systemd-nspawn@$N.service" 2>/dev/null
  machinectl terminate "$N" 2>/dev/null
  while iptables -D FORWARD -m comment --comment $N -j $FWD 2>/dev/null; do :; done
  iptables -F $FWD 2>/dev/null; iptables -X $FWD 2>/dev/null
  while iptables -t nat -D POSTROUTING -m comment --comment $N -j $NAT 2>/dev/null; do :; done
  iptables -t nat -F $NAT 2>/dev/null; iptables -t nat -X $NAT 2>/dev/null
  ip link del "$VE" 2>/dev/null
  rm -rf "$R" /etc/systemd/nspawn/$N.nspawn "/etc/systemd/system/systemd-nspawn@$N.service.d"
  systemctl daemon-reload
  "$0" status
  ;;
status)
  echo "left: unit=$(systemctl is-active systemd-nspawn@$N.service) machine=$(machinectl list --no-legend | grep -c $N) rootfs=$(ls -d $R 2>/dev/null) veth=$(ip -br link show $VE 2>/dev/null | wc -l) ipt=$(iptables -S | grep -c $N)/$(iptables -t nat -S | grep -c $N) cg=$(ls -d /sys/fs/cgroup/machine.slice/*$N* 2>/dev/null | wc -l) ch_procs=$(pgrep -c cloud-hyperviso) vfs_procs=$(pgrep -c virtiofsd) taps=$(ip -o link | grep -c ': tap')"
  ;;
esac
