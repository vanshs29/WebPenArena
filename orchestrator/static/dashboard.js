const METRICS = [
  { key: "exploration", cls: "exploration", label: "Exploration" },
  { key: "reconnaissance", cls: "reconnaissance", label: "Recon" },
  { key: "vulnerability_detection", cls: "vulndetect", label: "Vuln Detect" },
  { key: "exploitation", cls: "exploitation", label: "Exploitation" },
];

const totalsEl = document.getElementById("totals");
const gridEl = document.getElementById("app-grid");
const statusBadgeEl = document.getElementById("status-badge");
const cardTpl = document.getElementById("tpl-app-card");

const cardsById = new Map();

function fmt(n) {
  return Number(n ?? 0).toFixed(2);
}

function renderTotals(totals, nResponded, nTotal) {
  totalsEl.innerHTML = "";
  for (const m of METRICS) {
    const tile = document.createElement("div");
    tile.className = "stat-tile";
    tile.innerHTML = `
      <div class="label"><span class="dot dot-${m.cls}"></span>${m.label}</div>
      <div class="value">${totals[m.key] ?? "0.00 / 0"}</div>
    `;
    totalsEl.appendChild(tile);
  }
  statusBadgeEl.textContent = `${nResponded}/${nTotal} apps responding`;
}

function buildCard(app) {
  const node = cardTpl.content.firstElementChild.cloneNode(true);
  node.dataset.id = app.id;

  const meters = node.querySelector(".meters");
  for (const m of METRICS) {
    const row = document.createElement("div");
    row.className = "meter-row";
    row.innerHTML = `
      <div class="meter-label"><span class="dot dot-${m.cls}"></span>${m.label}</div>
      <div class="meter-track"><div class="meter-fill ${m.cls}" data-metric="${m.key}" style="width:0%"></div></div>
      <div class="meter-value" data-metric-value="${m.key}">–</div>
    `;
    meters.appendChild(row);
  }

  node.querySelector(".btn-launch").addEventListener("click", (e) => withButton(e.target, () => launchOne(app.id)));
  node.querySelector(".btn-rebuild").addEventListener("click", (e) => withButton(e.target, () => rebuildOne(app.id)));
  node.querySelector(".btn-reset").addEventListener("click", () => resetOne(app.id));
  node.querySelector(".btn-stop").addEventListener("click", () => stopOne(app.id));
  node.querySelector(".btn-events").addEventListener("click", () => {
    node.classList.toggle("events-open");
  });

  gridEl.appendChild(node);
  cardsById.set(app.id, node);
  return node;
}

function patchCard(node, app) {
  node.querySelector(".app-name").textContent = app.name;
  node.querySelector(".app-desc").textContent = app.description;
  node.querySelector(".app-port").textContent = app.running && app.host_port ? `Port ${app.host_port}` : "";

  const pill = node.querySelector(".status-pill");
  const score = app.score;
  let statusClass, statusText;
  if (!app.running) {
    statusClass = "status-not-launched";
    statusText = "not launched";
  } else if (score === null) {
    statusClass = "status-unreachable";
    statusText = "not responding";
  } else {
    statusClass = "status-running";
    statusText = app.status || "running";
  }
  pill.className = `status-pill ${statusClass}`;
  pill.textContent = statusText;
  node.classList.toggle("is-offline", !app.running || score === null);

  const scores = score ? score.scores : {};
  for (const m of METRICS) {
    const fill = node.querySelector(`.meter-fill[data-metric="${m.key}"]`);
    const val = node.querySelector(`[data-metric-value="${m.key}"]`);
    const v = scores[m.key];
    if (v === undefined) {
      fill.style.width = "0%";
      val.textContent = "–";
    } else {
      fill.style.width = `${Math.min(v, 1) * 100}%`;
      val.textContent = fmt(v);
    }
  }

  const events = score ? (score.events || []) : [];
  node.querySelector(".event-count").textContent = events.length ? `(${events.length})` : "";
  const list = node.querySelector(".events-list");
  list.innerHTML = "";
  for (const ev of events.slice(0, 20)) {
    const li = document.createElement("li");
    li.innerHTML = `<span>${ev.detail ?? ""}</span><span class="event-metric">${ev.metric}</span>`;
    list.appendChild(li);
  }

  const scoreboardLink = node.querySelector(".btn-scoreboard");
  if (app.score_url) {
    scoreboardLink.href = app.score_url;
    scoreboardLink.classList.remove("is-disabled");
  } else {
    scoreboardLink.removeAttribute("href");
    scoreboardLink.classList.add("is-disabled");
  }

  const launchBtn = node.querySelector(".btn-launch");
  const resetBtn = node.querySelector(".btn-reset");
  const stopBtn = node.querySelector(".btn-stop");
  launchBtn.hidden = app.running;
  resetBtn.hidden = !app.running;
  stopBtn.hidden = !app.running;
}

function renderApps(apps) {
  if (apps.length === 0) {
    gridEl.innerHTML = '<p class="empty-state">No registered apps.</p>';
    return;
  }
  for (const app of apps) {
    let node = cardsById.get(app.id);
    if (!node) node = buildCard(app);
    patchCard(node, app);
  }
}

async function refresh() {
  try {
    const res = await fetch("/api/scoreboard");
    const data = await res.json();
    renderTotals(data.totals, data.n_responded, data.n_total);
    renderApps(data.apps);
  } catch (e) {
    statusBadgeEl.textContent = "dashboard offline?";
  }
}

async function withButton(btn, fn) {
  btn.disabled = true;
  const original = btn.textContent;
  btn.textContent = "Working…";
  try {
    await fn();
  } finally {
    btn.disabled = false;
    btn.textContent = original;
    refresh();
  }
}

async function launchOne(id) {
  await fetch(`/api/apps/${id}/launch`, { method: "POST" });
  refresh();
}

async function rebuildOne(id) {
  await fetch(`/api/apps/${id}/rebuild`, { method: "POST" });
  refresh();
}

async function resetOne(id) {
  if (!confirm(`Reset scoring state for "${id}"? This clears its events and re-seeds app data.`)) return;
  await fetch(`/api/apps/${id}/reset`, { method: "POST" });
  refresh();
}

async function stopOne(id) {
  if (!confirm(`Stop and remove the running container for "${id}"?`)) return;
  await fetch(`/api/apps/${id}/stop`, { method: "POST" });
  refresh();
}

document.getElementById("btn-launch-all").addEventListener("click", (e) => {
  withButton(e.target, () => fetch("/api/launch-all", { method: "POST" }));
});

document.getElementById("btn-rebuild-all").addEventListener("click", (e) => {
  withButton(e.target, () => fetch("/api/rebuild-all", { method: "POST" }));
});

document.getElementById("btn-reset-all").addEventListener("click", (e) => {
  if (!confirm("Reset scoring state for ALL running apps? This clears events and re-seeds app data.")) return;
  withButton(e.target, () => fetch("/api/reset-all", { method: "POST" }));
});

document.getElementById("btn-stop-all").addEventListener("click", (e) => {
  if (!confirm("Stop and remove ALL running benchmark containers?")) return;
  withButton(e.target, () => fetch("/api/stop-all", { method: "POST" }));
});

refresh();
setInterval(refresh, 2000);
