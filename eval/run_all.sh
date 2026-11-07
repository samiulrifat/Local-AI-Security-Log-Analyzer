#!/usr/bin/env bash
# Runs the accuracy checks under the server limits and saves results in eval/results.
# Two at a time on separate cores, each one pinned to its own 2 CPUs.
cd "$(dirname "$0")/.."
SUPPLIED=samples/Cultive8_Workspace_Agrigen_Server.log
OTHER=samples/other_format.log

one() {  # name, file, cpus, port, extra args
    local name=$1 file=$2 cpus=$3 port=$4; shift 4
    CPUS=$cpus LLAMA_PORT=$port ./scripts/run_limited.sh .venv/bin/python scripts/analyze.py "$file" "$@" \
        --out "eval/results/$name.json" > "eval/results/$name.txt" 2>&1
    .venv/bin/python eval/score.py "eval/results/$name.json" "$(basename "$file")" >> "eval/results/$name.txt" 2>&1
}

mkdir -p eval/results
.venv/bin/python eval/make_other_log.py
one supplied_2b            "$SUPPLIED" 0,1 8091 &
one other_format_2b        "$OTHER"    2,3 8092 &
wait
USE_RULES=0 one supplied_2b_rules_off     "$SUPPLIED" 0,1 8091 &
USE_RULES=0 one other_format_2b_rules_off "$OTHER"    2,3 8092 &
wait
one supplied_0.8b          "$SUPPLIED" 0,1 8091 --model qwen-0.8b
tail -n 1 eval/results/*.txt
