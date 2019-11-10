#!/bin/bash

set -ex

mkdir -p /opt/kadena/bin
mkdir -p /opt/kadena/etc/systemd
install bin/blake2s-gpu-miner /opt/kadena/bin
cat > /opt/kadena/etc/systemd/chainweb-gpu-miner@.service <<EOF
[Unit]
Description=Chainweb GPU Miner (%I)
[Service]
SyslogIdentifier=chainweb-gpu-miner@%i
Type=simple
ExecStart=/opt/kadena/bin/blake2s-gpu-miner --server --unix-domain-ns chainweb-gpu-miner%i
KillMode=mixed
Restart=always
RestartSec=5
TimeoutStopSec=5
[Install]
WantedBy=default.target
EOF
NUMINSTANCES=1

ln -fst /etc/systemd/system/ /opt/kadena/etc/systemd/chainweb-gpu-miner@.service
systemctl daemon-reload

for i in $(seq 0 $(($NUMINSTANCES - 1))); do
systemctl enable chainweb-gpu-miner@$i
systemctl stop chainweb-gpu-miner@$i || true
systemctl start chainweb-gpu-miner@$i
done
