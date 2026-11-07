#!/usr/bin/env bash
# Runs any command with the same limits as the target server: 2 CPUs and 4 GB of
# RAM. The kernel enforces these, so going over the memory limit would kill it.
# example: ./scripts/run_limited.sh ./scripts/run.sh
exec systemd-run --user --scope --quiet -p MemoryMax=4G -p MemorySwapMax=0 \
    taskset -c "${CPUS:-0,1}" "$@"
