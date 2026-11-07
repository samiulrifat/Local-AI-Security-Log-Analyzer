// Plain JS, no libraries, so the page works with no internet.
// Log text and model answers are only ever put in the page with textContent,
// never as HTML, because they can contain anything.

const $ = (id) => document.getElementById(id);
const CONTEXT = 2048;

let jobId = null;
let lastData = null;
let pollTimer = null;
let highlight = null; // lines of the finding being looked at

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function show(section) {
  for (const id of ["home", "ready", "running", "report"]) $(id).hidden = id !== section;
}

async function api(path, options) {
  const response = await fetch(path, options);
  if (!response.ok) {
    let message = "Something went wrong.";
    try { message = (await response.json()).detail || message; } catch (e) { /* not json */ }
    throw new Error(message);
  }
  return response.json();
}

/* ---------- barcode strip ---------- */

function drawStrip() {
  const total = lastData && lastData.job.total_lines;
  if (!total) {
    startRain();
    return;
  }
  stopRain();

  const canvas = $("strip");
  const width = canvas.clientWidth;
  const height = canvas.clientHeight;
  const dpr = window.devicePixelRatio || 1;
  canvas.width = width * dpr;
  canvas.height = height * dpr;
  const ctx = canvas.getContext("2d");
  ctx.scale(dpr, dpr);
  ctx.clearRect(0, 0, width, height);

  const parts = lastData.parts;
  const hits = hitLines();
  const barWidth = Math.max(1, width / total - 1);

  for (let line = 1; line <= total; line++) {
    const part = parts.find((p) => line >= p.first_line && line <= p.last_line);
    let color = "#0f3d1c";
    if (part && part.status === "done") color = "#0e9e3a";
    if (part && part.status === "failed") color = "#6b1d1d";
    if (highlight) color = "#0b2912";
    if (highlight ? highlight.has(line) : hits.has(line)) color = "#ff3131";
    const running = part && part.status === "running" && !highlight;
    if (running && color === "#0f3d1c") color = "#00ff41";
    ctx.fillStyle = color;
    const barHeight = running ? height * (0.55 + 0.45 * Math.abs(Math.sin(Date.now() / 300 + line / 3))) : height;
    ctx.fillRect(((line - 1) / total) * width, height - barHeight, barWidth, barHeight);
  }
}

// when there's no file yet, characters from log lines fall down the strip
const RAIN_CHARS = "0123456789abcdef.:/[]{}=";
const RAIN_SIZE = 14;
let rainTimer = null;
let rainDrops = [];

function startRain() {
  if (rainTimer) return;
  const canvas = $("strip");
  canvas.width = canvas.clientWidth;
  canvas.height = canvas.clientHeight;
  rainDrops = Array.from({ length: Math.ceil(canvas.width / RAIN_SIZE) }, () => Math.random() * -30);

  if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
    for (let i = 0; i < 40; i++) rainStep();
    return;
  }
  rainTimer = setInterval(rainStep, 70);
}

function stopRain() {
  clearInterval(rainTimer);
  rainTimer = null;
}

function rainStep() {
  const canvas = $("strip");
  const ctx = canvas.getContext("2d");
  // a see-through black layer each frame is what leaves the fading trails
  ctx.fillStyle = "rgba(0, 0, 0, 0.14)";
  ctx.fillRect(0, 0, canvas.width, canvas.height);
  ctx.font = `${RAIN_SIZE}px monospace`;

  rainDrops.forEach((row, column) => {
    const char = RAIN_CHARS[Math.floor(Math.random() * RAIN_CHARS.length)];
    // now and then a red one, same colour attacks get in the report
    ctx.fillStyle = Math.random() < 0.004 ? "#ff3131" : Math.random() < 0.1 ? "#d6ffe0" : "#00ff41";
    ctx.fillText(char, column * RAIN_SIZE, row * RAIN_SIZE);
    rainDrops[column] = row * RAIN_SIZE > canvas.height && Math.random() > 0.96 ? 0 : row + 1;
  });
}

function hitLines() {
  const lines = new Set();
  if (!lastData) return lines;
  if (lastData.report) {
    for (const finding of lastData.report.findings) {
      for (const stage of finding.evidence) stage.lines.forEach((n) => lines.add(n));
    }
  } else {
    for (const event of lastData.events || []) event.lines.forEach((n) => lines.add(n));
  }
  return lines;
}

$("strip").addEventListener("mousemove", (event) => {
  const total = lastData && lastData.job.total_lines;
  if (!total) return;
  const rect = event.target.getBoundingClientRect();
  const line = Math.max(1, Math.ceil(((event.clientX - rect.left) / rect.width) * total));
  $("stripInfo").textContent = `line ${line} of ${total}` + describeLine(line);
});

function describeLine(line) {
  if (!lastData.report) return "";
  for (const finding of lastData.report.findings) {
    for (const stage of finding.evidence) {
      if (stage.lines.includes(line)) return ` · ${finding.actor} · ${stage.label}`;
    }
  }
  return "";
}

window.addEventListener("resize", () => {
  stopRain();
  drawStrip();
});
setInterval(() => {
  // keeps the bars of the running part moving
  if (lastData && lastData.parts.some((p) => p.status === "running")) drawStrip();
}, 120);

/* ---------- upload ---------- */

async function upload(file) {
  $("uploadError").hidden = true;
  const form = new FormData();
  form.append("file", file);
  try {
    const job = await api("/api/jobs", { method: "POST", body: form });
    location.hash = job.id;
  } catch (error) {
    $("uploadError").textContent = error.message;
    $("uploadError").hidden = false;
  }
}

$("file").addEventListener("change", (event) => {
  if (event.target.files[0]) upload(event.target.files[0]);
  event.target.value = "";
});

for (const name of ["dragover", "dragenter"]) {
  document.addEventListener(name, (event) => {
    event.preventDefault();
    $("drop").classList.add("over");
  });
}
document.addEventListener("dragleave", () => $("drop").classList.remove("over"));
document.addEventListener("drop", (event) => {
  event.preventDefault();
  $("drop").classList.remove("over");
  if (event.dataTransfer.files[0] && !$("home").hidden) upload(event.dataTransfer.files[0]);
});

/* ---------- buttons ---------- */

$("startBtn").addEventListener("click", async () => {
  await api(`/api/jobs/${jobId}/start`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ model: $("model").value }),
  });
  poll();
});

$("cancelBtn").addEventListener("click", () => api(`/api/jobs/${jobId}/cancel`, { method: "POST" }));

async function retry() {
  await api(`/api/jobs/${jobId}/retry`, { method: "POST" });
  poll();
}
$("retryBtn").addEventListener("click", retry);
$("reportRetryBtn").addEventListener("click", retry);

/* ---------- screens ---------- */

async function route() {
  clearTimeout(pollTimer);
  jobId = location.hash.slice(1) || null;
  lastData = null;
  highlight = null;
  $("stripInfo").textContent = "";
  if (jobId) {
    poll();
  } else {
    show("home");
    drawStrip();
    loadHistory();
  }
}
window.addEventListener("hashchange", route);

async function loadHistory() {
  const jobs = await api("/api/jobs");
  const box = $("history");
  box.replaceChildren();
  if (jobs.length) box.append(el("h2", "", "Earlier runs"));
  for (const job of jobs) {
    const row = el("a", "job-row");
    row.href = `#${job.id}`;
    row.append(el("span", "", job.filename), el("span", "", job.status));
    box.append(row);
  }
}

async function poll() {
  clearTimeout(pollTimer);
  let data;
  try {
    data = await api(`/api/jobs/${jobId}`);
  } catch (error) {
    location.hash = "";
    return;
  }
  lastData = data;
  const status = data.job.status;

  if (status === "uploaded") {
    renderReady(data);
  } else if (status === "done") {
    renderReport(data);
  } else {
    renderRunning(data);
    if (!["failed", "cancelled"].includes(status)) pollTimer = setTimeout(poll, 2000);
  }
  drawStrip();
}

function renderReady(data) {
  show("ready");
  $("readyName").textContent = data.job.filename;
  $("readySize").textContent = `${(data.job.size / 1024).toFixed(1)} KB. Reading takes a few minutes on two CPU cores.`;
}

function renderRunning(data) {
  show("running");
  const { job, parts } = data;
  const done = parts.filter((p) => p.status === "done" || p.status === "failed").length;
  const percent = parts.length ? Math.round((done / parts.length) * 100) : 0;
  const stopped = ["failed", "cancelled"].includes(job.status);

  $("progressBig").textContent = stopped ? job.status : job.status === "reporting" ? "Writing up" : `${percent}%`;
  $("progressText").textContent = progressText(job, parts, done);
  $("cancelBtn").hidden = stopped;
  $("retryBtn").hidden = !stopped;
  $("runError").hidden = !job.error;
  $("runError").textContent = job.error || "";

  const hits = $("hits");
  hits.replaceChildren();
  for (const event of data.events.slice(-12).reverse()) {
    const row = el("li");
    row.append(el("span", "", event.type.replace(/_/g, " ")));
    row.append(` ${event.actor} on lines ${event.lines.join(", ")}`);
    hits.append(row);
  }
  if (!data.events.length) hits.append(el("li", "muted", "nothing yet"));

  const box = $("parts");
  box.replaceChildren();
  for (const part of parts) box.append(partRow(part));
}

function progressText(job, parts, done) {
  if (job.status === "queued") return "Waiting for the model.";
  if (job.status === "splitting") return "Counting tokens and splitting the file.";
  if (job.status === "reporting") return "All parts read. Linking events across the file and checking each suspect.";
  if (job.status === "cancelled") return `Stopped after ${done} of ${parts.length} parts. Finished parts are saved.`;
  if (job.status === "failed") return `Stopped after ${done} of ${parts.length} parts. Finished parts are saved.`;
  return `Part ${Math.min(done + 1, parts.length)} of ${parts.length}. One model call at a time, 2048 tokens each.`;
}

function partRow(part) {
  const row = el("div", `part ${part.status}`);
  row.append(el("span", "", part.idx + 1));
  row.append(el("span", "", `L${part.first_line}-L${part.last_line}`));
  const meter = el("div", "meter");
  const used = part.prompt_tokens + part.reply_tokens;
  const fill = el("div");
  fill.style.width = `${(used / CONTEXT) * 100}%`;
  meter.append(fill);
  row.append(meter);
  row.append(el("span", "part-tokens", used ? `${used}/${CONTEXT}` : part.status));
  row.append(el("span", "", part.seconds ? `${Math.round(part.seconds)}s` : ""));
  if (part.status === "failed") row.title = part.error || "";
  return row;
}

/* ---------- report ---------- */

function renderReport(data) {
  show("report");
  const report = data.report;
  const count = report.findings.length;

  const big = $("reportBig");
  big.replaceChildren();
  if (count) {
    big.append(el("em", "", count), count === 1 ? " attacker" : " attackers");
  } else {
    big.textContent = "All clear";
  }
  $("reportSummary").textContent = report.summary;

  const failed = report.coverage.failed_parts;
  $("coverage").hidden = !failed.length;
  $("reportRetryBtn").hidden = !failed.length;
  if (failed.length) {
    const ranges = failed.map((p) => `L${p.first_line}-L${p.last_line}`).join(", ");
    $("coverage").textContent = `The model couldn't finish ${ranges}. Rule checks still covered those lines, but this report is incomplete.`;
  }

  const box = $("findings");
  box.replaceChildren();
  report.findings.forEach((finding) => box.append(findingBlock(finding, data.job.total_lines)));

  const reviewed = $("reviewed");
  reviewed.replaceChildren();
  for (const item of report.reviewed) {
    const row = el("div", "review");
    const left = el("div");
    left.append(el("div", "", item.label));
    left.append(el("div", "tag", item.lines.length === 1 ? `L${item.lines[0]}` : `${item.lines.length} lines, first L${item.lines[0]}`));
    row.append(left, el("div", "muted", item.reason));
    reviewed.append(row);
  }
  if (!report.reviewed.length) reviewed.append(el("p", "muted", "Nothing else stood out."));

  const stats = data.stats;
  const seconds = Math.round(data.job.finished - data.job.started);
  $("runStats").textContent =
    `${data.parts.length} parts · ${stats.calls} model calls · biggest call ${stats.biggest_call}/${CONTEXT} tokens · ` +
    `${data.job.total_tokens} log tokens sent · ${seconds}s total, ${Math.round(stats.seconds)}s in the model · ` +
    `peak ram ${(report.peak_ram_mb / 1024).toFixed(2)} GB · model ${data.job.model}` +
    (report.rules_used ? "" : " · rules off");

  const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
  $("download").href = URL.createObjectURL(blob);
}

function findingBlock(finding, totalLines) {
  const block = el("article", "finding");
  const head = el("div", "finding-head");
  head.append(el("div", `sev sev-${finding.severity}`, finding.severity));

  const title = el("div");
  title.append(el("h3", "attack", finding.attack_type));
  const users = finding.users.length ? ` · ${finding.users.join(", ")}` : "";
  const actor = el("div", "actor", finding.actor + users);
  title.append(actor);
  head.append(title);
  block.append(head);

  const body = el("div", "finding-body");
  const lines = finding.evidence.flatMap((stage) => stage.lines);
  body.append(miniStrip(lines, totalLines));
  const spread = finding.parts.length > 1 ? `Linked across parts ${finding.parts.join(", ")}.` : `In part ${finding.parts[0]}.`;
  body.append(el("div", "actor tag", `${spread} ${finding.certainty}. Found by ${finding.found_by}.`));
  body.append(labelled("Why", finding.reason));
  body.append(labelled("Do this", finding.action));
  if (finding.model_disagreed) {
    body.append(el("p", "muted", "The model didn't call this an attack on final review, the patterns in the log did."));
  }
  for (const stage of finding.evidence) body.append(stageBlock(stage));
  block.append(body);

  // pointing at a finding lights up its lines on the big strip
  block.addEventListener("mouseenter", () => {
    highlight = new Set(lines);
    $("stripInfo").textContent = `${finding.actor}: ${lines.length} lines`;
    drawStrip();
  });
  block.addEventListener("mouseleave", () => {
    highlight = null;
    $("stripInfo").textContent = "";
    drawStrip();
  });
  return block;
}

function labelled(label, text) {
  const line = el("p");
  line.append(el("span", "label", `${label}: `), text);
  return line;
}

function miniStrip(lines, total) {
  const canvas = el("canvas", "mini");
  requestAnimationFrame(() => {
    const width = canvas.clientWidth;
    canvas.width = width;
    canvas.height = 14;
    const ctx = canvas.getContext("2d");
    ctx.fillStyle = "#0f3d1c";
    ctx.fillRect(0, 6, width, 2);
    ctx.fillStyle = "#ff3131";
    for (const line of lines) ctx.fillRect(Math.floor(((line - 1) / total) * width), 0, 2, 14);
  });
  return canvas;
}

function stageBlock(stage) {
  const block = el("div", "stage");
  block.append(el("div", "stage-name", stage.label));
  const links = el("div", "stage-lines");
  const raw = el("pre", "raw");
  raw.hidden = true;

  const shown = stage.lines.slice(0, 40);
  for (const number of shown) {
    const link = el("a", "", `L${number}`);
    link.addEventListener("click", () => showLines(raw, [number]));
    links.append(link);
  }
  if (stage.lines.length > 40) links.append(`+${stage.lines.length - 40} more`);
  if (stage.lines.length > 1) {
    const all = el("a", "", "show all");
    all.addEventListener("click", () => showLines(raw, shown));
    links.append(all);
  }

  block.append(links, raw);
  return block;
}

async function showLines(target, numbers) {
  const found = await api(`/api/jobs/${jobId}/lines?numbers=${numbers.join(",")}`);
  target.textContent = numbers.map((n) => `L${n}  ${found[n] ?? ""}`).join("\n");
  target.hidden = false;
}

/* ---------- header status ---------- */

async function refreshSystem() {
  try {
    const info = await api("/api/system");
    const select = $("model");
    if (!select.options.length) {
      for (const model of info.models) {
        const option = el("option", "", model.label + (model.installed ? "" : " (not installed)"));
        option.value = model.key;
        option.disabled = !model.installed;
        select.append(option);
      }
      select.value = info.active_model;
    }
    const gb = (mb) => (mb / 1024).toFixed(2);
    const status = $("status");
    status.replaceChildren();
    status.append(info.model_ready ? "model ready" : "model starting");
    status.append(" · ram ", el("b", "", `${gb(info.ram_mb)}`), " / 4.00 GB · peak ", el("b", "", gb(info.peak_ram_mb)));
  } catch (error) {
    $("status").textContent = "server not reachable";
  }
}

refreshSystem();
setInterval(refreshSystem, 4000);
route();
