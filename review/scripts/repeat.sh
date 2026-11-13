#!/bin/sh
# Repeats the review measurements on a given copy of the tool. usage: repeat.sh TOOLDIR BINDIR OUTDIR
S=$1; B=$2; O=$3; H=$(cd "$(dirname "$0")" && pwd); W=$(mktemp -d)
mkdir -p "$O"
for sc in dry-regtest dry-main-dice real-netns; do
  timeout 600 python3 -I "$H/t04_trace.py" "$S" "$B" "$W/trace" $sc > "$O/04-trace-$sc.txt" 2>&1
done
rm -rf "$W/trace"
timeout 900 python3 -I "$H/t05_terminal.py" "$S" "$B" "$W/term" > "$O/05-terminal.txt" 2>&1
timeout 600 python3 -I "$H/t06_failures.py" "$S" "$B" "$W/fail" > "$O/06-failures.txt" 2>&1
P="python3 -I $H/t07_netcheck.py $S"
LO="mount -t sysfs sysfs /sys; ip link set lo up"
MK="$LO; ip link add eth9 type veth peer name eth9p; ip addr add 192.168.50.2/24 dev eth9; ip link set eth9 up; ip link set eth9p up"
{ echo "What the offline check sees on Linux (network namespaces, kernel $(uname -r))"
  echo "1. only the loopback interface"; unshare -n -m sh -c "$LO; $P"
  echo "2. an interface that is up, has carrier and an address (192.168.50.2/24), but no default route (a LAN without a gateway)"
  unshare -n -m sh -c "$MK; $P"
  echo "3. the same interface with a default route through 192.168.50.1"
  unshare -n -m sh -c "$MK; ip route add default via 192.168.50.1; $P"
  echo "4. default route only in a separate routing table (policy routing, as some VPN set-ups do), none in the main table"
  unshare -n -m sh -c "$MK; ip route add default via 192.168.50.1 table 51820; ip rule add not fwmark 51820 table 51820; ip route get 8.8.8.8 2>&1 | head -1 | sed 's/^/      kernel would route 8.8.8.8 as: /'; $P"
  echo "5. a route to 8.0.0.0/7 only"
  unshare -n -m sh -c "$MK; ip route add 8.0.0.0/7 via 192.168.50.1; $P"
  echo "6. this machine as it is (online)"; $P
} > "$O/07-offline-check.txt" 2>&1
for i in 1 2 3 4 5 6; do echo "--- attempt $i"; timeout 300 python3 -I "$H/t08_port_owner.py" "$S" "$B" "$W/port" 2>&1 | cut -c1-200; done > "$O/08-port-owner.txt" 2>&1
rm -rf "$W"
echo finished > "$O/.done"
