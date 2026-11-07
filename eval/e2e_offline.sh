#!/usr/bin/env bash
# Full run through the web API with networking switched off, to show the app works
# offline and survives failures. Start it with: unshare -rn bash eval/e2e_offline.sh
# (unshare -rn gives it a private network with no route to the internet)
#
# What it does: tries bad uploads, starts a real analysis, kills the model in the
# middle, then kills the whole backend and starts it again to check it resumes.
cd "$(dirname "$0")/.."
ip link set lo up

PORT=8010
export LLAMA_PORT=8090
BASE="http://127.0.0.1:$PORT"
SAMPLE=samples/Cultive8_Workspace_Agrigen_Server.log
BAD=$(mktemp -d)

start_app() {
    PORT=$PORT taskset -c 0,1 ./scripts/run.sh >> data/e2e-app.log 2>&1 &
    APP_PID=$!
    until curl -s -m 2 "$BASE/api/system" | grep -q '"model_ready":true'; do sleep 1; done
}

parts_done() {
    curl -s "$BASE/api/jobs/$JOB" | .venv/bin/python -c "
import json, sys
data = json.load(sys.stdin)
print(data['job']['status'], sum(p['status'] == 'done' for p in data['parts']), len(data['parts']))"
}

wait_for_parts() {  # wait until at least $1 parts are done
    while true; do
        read -r status done_count total <<< "$(parts_done)"
        [ "${done_count:-0}" -ge "$1" ] && return
        [ "$status" = "done" ] && return
        sleep 2
    done
}

echo "== internet check (should fail)"
curl -s -m 3 https://huggingface.co > /dev/null && echo "ONLINE, test is not valid" || echo "no internet, good"

start_app
echo "== bad uploads, each should be refused with a clear message"
head -c 2000 /dev/urandom > "$BAD/random.log"
: > "$BAD/empty.log"
printf '\n\n\n' > "$BAD/blank.txt"
echo hello > "$BAD/notes.pdf"
head -c 21000000 /dev/zero | tr '\0' 'a' > "$BAD/huge.log"
for file in random.log empty.log blank.txt notes.pdf huge.log; do
    printf '%-12s ' "$file"
    curl -s -w ' [%{http_code}]\n' -F "file=@$BAD/$file" "$BASE/api/jobs"
done

echo "== good upload and start"
JOB=$(curl -s -F "file=@$SAMPLE" "$BASE/api/jobs" | .venv/bin/python -c "import json,sys; print(json.load(sys.stdin)['id'])")
echo "job $JOB"
curl -s -X POST -H 'Content-Type: application/json' -d '{"model":"qwen-2b"}' "$BASE/api/jobs/$JOB/start"; echo
echo "second start should be refused:"
curl -s -w ' [%{http_code}]\n' -X POST -H 'Content-Type: application/json' -d '{"model":"qwen-2b"}' "$BASE/api/jobs/$JOB/start"

wait_for_parts 1
echo "== after part 1: $(parts_done)"

echo "== killing the model server in the middle of a call"
sleep 8
pkill -9 -f "[l]lama-server.*--port $LLAMA_PORT"
wait_for_parts 2
echo "after the kill: $(parts_done)"

echo "== killing the whole backend with kill -9"
sleep 5
kill -9 $APP_PID
pkill -9 -f "[l]lama-server.*--port $LLAMA_PORT"
sleep 1
BEFORE=$(.venv/bin/python -c "
import sqlite3
print(sqlite3.connect('data/app.db').execute(\"select count(*) from parts where job_id='$JOB' and status='done'\").fetchone()[0])")
echo "parts saved on disk before restart: $BEFORE"

start_app
echo "== restarted, status now: $(parts_done)"
while [ "$(parts_done | cut -d' ' -f1)" != "done" ]; do sleep 5; done
echo "== finished: $(parts_done)"

curl -s "$BASE/api/jobs/$JOB" > data/e2e-result.json
.venv/bin/python - <<PY
import json
data = json.load(open("data/e2e-result.json"))
print("failed calls logged (from the kills):")
for call in data["calls"]:
    if not call["ok"]:
        print("  ", call["kind"], call["label"], call["note"])
print("stats", data["stats"])
print("peak ram mb", data["report"]["peak_ram_mb"])
for f in data["report"]["findings"]:
    print(f["severity"], f["actor"], f["attack_type"], "parts", f["parts"], f["found_by"])
PY
echo "job id: $JOB"
echo "$JOB" > data/e2e-job.txt

rm -rf "$BAD"
kill $APP_PID
wait 2>/dev/null
