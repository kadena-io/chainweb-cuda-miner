# GPU external mining binary for Kadena's Chainweb

## How to build

```
# make NVCC=/path/to/nvcc
```

## Setup instructions for chainweb-miner

The path and args to the external mining binary can be provided to
`chainweb-miner gpu` using `--miner-path` and `--miner-args`.


## Running systemd unix socket service

In order to amortize GPU startup latency, the mining code can fork a unix
socket server to listen for requests from `chainweb-miner`. To install:

```
sudo ./install.sh
```

This will copy systemd service files to `/opt/kadena`, and setup `systemctl` to
run the mining code as a service at boot. If you want to run multiple
instances, you can tweak the service file as desired (and there are
`--num-devices` and `--starting-device` flags for the cuda binary).

## Connecting to running systemd service

`chainweb-gpu-miner` requires the following flags to connect to client:

```
--client --unix-domain-ns=$NS
```

The default unix socket namespace is `chainweb-gpu-miner0`, but if you want to
set up one-chain-per-miner, you'll have to pass `--miner-args="--client
--unix-domain-ns=$NS"` (or something similar) when you are setting up
`chainweb-miner`.

## Acceptance test

There is an acceptance test for chainweb mining code in the `cwtool` binary
provided in the main `chainweb-node` repository. Run `cwtool test-miner` for
instructions.
