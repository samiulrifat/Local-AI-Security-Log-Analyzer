# logsift

A web app that finds possible attacks in server logs using a small language model running on the same machine. Logs are bigger than the model can read at once, so the app splits them up, analyses each part, carries facts forward, and combines everything into one report.

No cloud APIs. After setup it works with no internet.

## Setup

Needs Linux x64, Python 3.10 or newer, `curl`, and about 3 GB of disk. No sudo and no GPU.

```bash
./scripts/setup.sh    # python packages, llama.cpp and two models (about 1.8 GB)
./scripts/run.sh      # then open http://127.0.0.1:8000
```

Drop a `.log` or `.txt` file on the page, press Analyze, and watch the bar strip fill in. There's a sample in `samples/`. It takes about 7 to 8 minutes on 2 CPU cores.

To run with the real limits enforced by the kernel (2 CPUs, 4 GB, no swap):

```bash
./scripts/run_limited.sh ./scripts/run.sh
```

Tests: `.venv/bin/python -m pytest`. They use a fake model, so they take about a second.

## Model

| | Qwen3.5 2B (default) | Qwen3.5 0.8B |
|---|---|---|
| File | `Qwen3.5-2B-Q4_K_M.gguf` from `unsloth/Qwen3.5-2B-GGUF` | `Qwen3.5-0.8B-Q4_0.gguf` from `ggml-org/Qwen3.5-0.8B-GGUF` |
| Size | 1.28 GB | 0.56 GB |
| Peak RAM, model only | 1.97 GB | 1.04 GB |
| Peak RAM, model and backend | 2.06 GB | about 1.1 GB |
| Supplied log, total time | 7.5 min | 4 min |

It runs on `llama-server` from llama.cpp (build b12182) with `-c 2048 -np 1 -t 2`. That means a 2048 token context, one call at a time, two threads. The prompt cache in RAM is turned off and so is thinking output.

You pick the model on the page before starting. I'd stay on 2B. The 0.8B is about twice as fast but its reasons are often wrong, for example saying an SQL injection "successfully executed" when every request got a 400. I didn't try Gemma 4 E2B. Its usable files are 2.5 to 3 GB, which leaves very little of the 4 GB for anything else.

## How it works

```
upload ──> check file ──> shorten lines, count tokens, plan parts
                                      │
             ┌────────────────────────┘
             ▼
   for each part, one call at a time:
     facts from earlier parts + this part's lines ──> model ──> JSON reply
     check the reply against the log, save to SQLite
             │
             ▼
   for each suspect: all its evidence from the whole file ──> model ──> verdict
   one call to sort ordinary errors
             │
             ▼
   one report: findings with evidence, plus what was checked and cleared
```

| File | What it does |
|---|---|
| `app/logfile.py` | Upload checks, parsing, shortening lines, grouping them for the prompt |
| `app/splitter.py` | Splits the log into parts by token count |
| `app/tracker.py` | The running record per IP that links events across parts |
| `app/prompts.py` | Everything sent to the model, and the reply formats |
| `app/replies.py` | Reads JSON (including broken JSON) and checks claims against the log |
| `app/llm.py` | Starts and talks to llama-server |
| `app/worker.py` | Runs a job from start to finish, with retries and resume |
| `app/report.py` | Builds the final findings |
| `app/db.py`, `app/main.py` | SQLite storage and web routes |

### Splitting

The real count for the supplied log is 39,896 tokens, about double what the brief estimates, because this tokenizer spends a token on nearly every digit of an IP or timestamp. So the first job is making lines shorter.

1. **Shorten each line.** Request ids, hostnames, browser strings and normal sizes get dropped, and URLs get decoded (double encoding too, so `%252e%252e%252f` reads `../`). That brings it to 11,856 tokens. The file on disk isn't changed and every line keeps its original number.
2. **Leave out routine lines.** Plain GET page views from a browser (200, 304, or the odd 404) become one note like `(14 normal page views left out)`. That leaves 3,703 tokens. The rule checks still read those lines, only the prompt skips them.
3. **Fill parts with whole entries.** Tokens are counted with the model's own tokenizer through `/tokenize`. A part ends when the next entry wouldn't fit. Entries are never cut between parts, and stack traces stay with the line above them.
4. **Overlap by two entries**, so events sitting on a boundary are seen together.

Exact repeats of the line above are merged and noted (L222 and L223 in the sample are the same event logged twice). A single entry over 1,200 characters is the one case that gets cut, and only in the prompt.

Parts only store line numbers and a byte offset. The text is read from disk when needed, so there's one copy of the log, and it's never all in memory.

### Token budget

| | Tokens |
|---|---|
| Context limit | 2048 |
| System prompt and chat template (measured when the job starts) | about 560 |
| Saved facts from earlier parts | up to 200 |
| Reserved for the reply | 340 |
| Safety gap | 32 |
| **Left for log text** | **about 916** |

Before every call the full prompt is built with the model's chat template and counted, and the reply limit is lowered if needed. The biggest call in the final run was 1,683 of 2,048. The page shows the tokens used by each part.

### Linking across parts

`app/tracker.py` keeps a record for each IP (or user or session if there's no IP): what it did, on which lines, and which accounts and clients it used. This is saved to SQLite after every part.

When a later part contains that IP, its history goes right in the prompt:

```
#2 203.0.113.44 EARLIER: failed_login x12 L5,L13..L189
L196 10:10:10 cultive8-workspace POST /api/v1/auth/login 200 python-requests/2.32.3 username=workspace.admin auth_result=success
```

Facts about IPs that aren't in the current part are left out, since nothing in that call could be linked to them.

At the end, each suspect gets one call with its history from the whole file, and the model decides if it's an attack. The report shows which parts the evidence came from, and a small strip shows where the lines sit in the file.

### What the model does and what the code does

Small models make things up, so nothing it says goes in the report unchecked.

**The model** reads each part and says what each group of lines is, gives a final verdict on each suspect with a severity and a reason, and sorts ordinary errors.

**The code** does the counting and checks the model:

- The reply format is a grammar built for each part. The model has to answer for every group, so it can't skip one or invent an IP.
- It doesn't cite line numbers at all. The evidence is whichever of that IP's lines actually fit the claim, so if it calls `GET /login 200` an SQL injection, no line fits and the claim is thrown out.
- A reason is replaced with plain facts from our records if it mentions some other IP, says an attack worked when nothing shows that, or describes an attack the actor never tried.
- Severity from the model is kept inside a range set by the evidence. A taken over account is always Critical, however the model rates it.
- Suggested actions are fixed text per kind of evidence, because the model's own kept naming accounts and tokens that weren't in the log.
- Signature rules (`app/tracker.py`) catch things the model misses. They describe techniques in general and know nothing about any specific log. Each finding says if it was found by `model + rules`, `rules only` or `model only`.

### Log text is data

- Control tokens like `<|im_end|>` are removed from all log text before it reaches a prompt, so a log line can't end the prompt early or start a fake system message.
- Prompts say the log is untrusted, and the model's replies can only change report text, nothing runs because of them.
- Text in a log telling the reader to ignore instructions becomes a finding (the sample has one at L217).
- The page only inserts log text and model text with `textContent`, never as HTML.

### Failures

| Problem | What happens |
|---|---|
| Wrong type, empty, binary, too large | Refused at upload with a clear message |
| Model timeout or crash | The server is restarted and the call retried, up to 3 attempts |
| Broken or cut off JSON | Everything up to the last complete item is kept, otherwise retried |
| A part keeps failing | Skipped, the rest continues, the report says which lines weren't read by the model, and there's a retry button |
| Backend restarts | The job continues from the first unfinished part |

Each part's findings, facts and status are saved in one SQLite transaction, so a crash loses at most the call in progress.

`eval/e2e_offline.sh` tests all of this through the web API with networking switched off: it tries five bad uploads, kills the model in the middle of a call, then kills the backend with `kill -9` and restarts it. The job carried on from part 2 of 5 and finished with the same findings.

## Accuracy

Measured with `eval/run_all.sh`, each run limited to 2 CPUs and 4 GB with no swap. The expected answers in `eval/expected.json` were worked out by hand and the app never reads that file. Normal traffic in the supplied log includes a health monitor, database timeouts, a bug that returns 500s, 503s during a deploy, and one mistyped password, none of which should be flagged.

| Setup | Supplied log (5 attackers) | Other format (3 attackers) | False alarms |
|---|---|---|---|
| Qwen 2B + rules (default) | 5 of 5 | 3 of 3 | 0 |
| Qwen 2B alone (`USE_RULES=0`) | 4 of 5 | 3 of 3 | 0 |
| Qwen 0.8B + rules | 5 of 5 | not run | 0 |

The other format is a generated nginx and sshd log with different attackers (`eval/make_other_log.py`), to check nothing is fitted to the supplied file.

What the default setup reports for the supplied log:

| Severity | Actor | Finding | Lines |
|---|---|---|---|
| Critical | 203.0.113.44 | Brute force, then account compromise and data theft | 12 failed logins from L5 to L189, success L196, admin L198, 2.8 MB export L201 |
| Medium | 203.0.113.72 | SQL injection | L29, L30, L32, and again at L222 |
| Medium | 203.0.113.90 | Scanning, path traversal and unauthorized access attempts | L54 to L69, L99 to L102 |
| Medium | 203.0.113.155 | Unusual request rate | L159 to L170 |
| Low | 203.0.113.201 | Prompt injection attempt | L217 |

These are one log plus one I generated, so they show the approach works, not how it would do on any log. Without the rules, the model misses the prompt injection on final review and under-rates severity (High rather than Critical for the account takeover), which is why the two work together.

## Known limits

- **Slow.** About 7.5 minutes for the supplied log, because that's what 2 CPU cores give you. A 20 MB log would take many hours.
- **Reasons can still be wrong.** The checks catch the worst of it, but a model this small can misdescribe details. Trust the evidence lines over the sentence. "Needs review" means the model and the rules didn't both agree.
- **Rules only know known patterns.** Something new has to be caught by the model alone.
- **Routine lines are hidden from the model.** An attacker using a browser user agent and plain successful GETs wouldn't be seen by the model. Rule checks for bursts and repeated 404s still see those lines.
- **Linking is per IP.** Failed logins on one account from many different IPs, or one session used from two IPs, aren't joined into one finding.
- **Very long entries** get cut to 1,200 characters in the prompt, though the rule checks read the whole line.
- **Only exact repeats next to each other** are merged as duplicates.
- **Tested on** Ubuntu with Python 3.14. The setup script only downloads Linux x64 builds.
- **No login on the page.** It only listens on `127.0.0.1`, don't expose it as it is.

## Optional extras that are in

- Resume after a restart
- RAM use and timing per model call on the page
- Fewer model calls: 5 parts rather than the 40 or so the raw log would need
- Switching between local models
