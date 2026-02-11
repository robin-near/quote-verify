const state = {
  result: null,
  activeCheckId: null,
  selectedPath: null,
  statusFilters: new Set(),
};

const inputEl = document.getElementById("quote-input");
const onlineToggleEl = document.getElementById("online-toggle");
const apiKeyEl = document.getElementById("api-key");
const baseUrlEl = document.getElementById("base-url");
const runBtnEl = document.getElementById("run-btn");
const statusLineEl = document.getElementById("status-line");
const summaryEl = document.getElementById("summary");
const checksEl = document.getElementById("checks");
const dumpEl = document.getElementById("dump");
const pathInfoEl = document.getElementById("path-info");
const example1Btn = document.getElementById("use-example-1");
const example2Btn = document.getElementById("use-example-2");

function setStatus(message, isError = false) {
  statusLineEl.textContent = message;
  statusLineEl.style.color = isError ? "#be2f31" : "#5b6572";
}

function statusIcon(status) {
  if (status === "pass") return "✓";
  if (status === "warn") return "!";
  if (status === "fail") return "✕";
  return "•";
}

const STATUS_ORDER = {
  fail: 0,
  warn: 1,
  pass: 2,
};

function getSortedChecks() {
  if (!state.result || !Array.isArray(state.result.checks)) return [];
  return state.result.checks
    .map((check, index) => ({ check, index }))
    .sort((a, b) => {
      const ar = Object.prototype.hasOwnProperty.call(STATUS_ORDER, a.check.status)
        ? STATUS_ORDER[a.check.status]
        : 99;
      const br = Object.prototype.hasOwnProperty.call(STATUS_ORDER, b.check.status)
        ? STATUS_ORDER[b.check.status]
        : 99;
      if (ar !== br) return ar - br;
      return a.index - b.index;
    })
    .map((item) => item.check);
}

function isStatusVisible(status) {
  if (state.statusFilters.size === 0) {
    return true;
  }
  return state.statusFilters.has(status);
}

function getVisibleChecks() {
  return getSortedChecks().filter((check) => isStatusVisible(check.status));
}

function ensureActiveCheckVisible() {
  const visible = getVisibleChecks();
  if (visible.length === 0) {
    state.activeCheckId = null;
    return;
  }

  const currentlyVisible = visible.some((check) => check.id === state.activeCheckId);
  if (currentlyVisible) {
    return;
  }

  const firstFail = visible.find((check) => check.status === "fail");
  state.activeCheckId = firstFail ? firstFail.id : visible[0].id;
}

function toggleStatusFilter(status) {
  if (state.statusFilters.has(status)) {
    state.statusFilters.delete(status);
  } else {
    state.statusFilters.add(status);
  }

  ensureActiveCheckVisible();
  renderSummary();
  renderChecks();
}

function pathIntersects(a, b) {
  if (!a || !b) return false;
  return (
    a === b ||
    a.startsWith(`${b}.`) ||
    a.startsWith(`${b}[`) ||
    b.startsWith(`${a}.`) ||
    b.startsWith(`${a}[`)
  );
}

function currentRefs() {
  if (!state.result) return [];
  const checks = state.result.checks || [];
  const active = checks.find((c) => c.id === state.activeCheckId);
  return active && Array.isArray(active.refs) ? active.refs : [];
}

function applyDumpHighlighting() {
  const refs = currentRefs();
  const selectedPath = state.selectedPath;
  dumpEl.querySelectorAll("[data-path]").forEach((node) => {
    const path = node.dataset.path;
    const highlighted = refs.some((ref) => path === ref);
    node.classList.toggle("highlight", highlighted);
    node.classList.toggle("selected", Boolean(selectedPath) && path === selectedPath);
  });
}

function setActiveCheck(checkId, scrollToRef = false, scrollInChecks = false, revealRefsOnSelect = true) {
  state.activeCheckId = checkId;
  renderChecks();
  applyDumpHighlighting();
  const check = state.result ? state.result.checks.find((c) => c.id === checkId) : null;
  if (scrollInChecks) {
    scrollToCheck(state.activeCheckId || checkId);
  }

  if (scrollToRef && check) {
    const refs = [...new Set((Array.isArray(check.refs) ? check.refs : []).filter((ref) => typeof ref === "string" && ref.length > 0))];
    refs.forEach((refPath) => {
      expandPath(refPath);
    });
    if (refs.length > 0) {
      scrollToPath(refs[0]);
      setSelectedPath(refs[0], false);
    }
    return;
  }

  // Plain check selection: expand all referenced nodes, then jump to the first one.
  if (revealRefsOnSelect && check && Array.isArray(check.refs) && check.refs.length > 0) {
    const refs = [...new Set(check.refs.filter((ref) => typeof ref === "string" && ref.length > 0))];
    refs.forEach((refPath) => {
      expandPath(refPath);
    });
    scrollToPath(refs[0]);
  }
}

function setSelectedPath(path, rerenderPanel = true) {
  state.selectedPath = path;
  applyDumpHighlighting();
  if (rerenderPanel) {
    renderPathInfo();
  }
}

function findPathNode(path) {
  return dumpEl.querySelector(`[data-path="${CSS.escape(path)}"]`);
}

function expandPath(path) {
  const target = findPathNode(path);
  if (!target) return;

  let parent = target.parentElement;
  while (parent) {
    if (parent.tagName === "DETAILS") {
      parent.open = true;
    }
    parent = parent.parentElement;
  }
}

function scrollToPath(path) {
  const target = findPathNode(path);
  if (!target) return;
  expandPath(path);

  target.scrollIntoView({ behavior: "smooth", block: "center" });
}

function scrollToCheck(checkId) {
  const target = checksEl.querySelector(`[data-check-id="${CSS.escape(checkId)}"]`);
  if (!target) return;
  target.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

function formatScalar(value) {
  if (value === null) return "null";
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  return JSON.stringify(value);
}

function renderNode(container, key, value, path, depth) {
  const isObject = value && typeof value === "object";

  if (isObject && !Array.isArray(value)) {
    const details = document.createElement("details");
    details.className = "dump-branch dump-node";
    details.dataset.path = path;
    details.open = depth < 2;

    const summary = document.createElement("summary");
    const keySpan = document.createElement("span");
    keySpan.className = "dump-key";
    keySpan.textContent = key;

    const metaSpan = document.createElement("span");
    metaSpan.className = "dump-meta";
    metaSpan.textContent = `{${Object.keys(value).length}}`;

    summary.appendChild(keySpan);
    summary.appendChild(metaSpan);
    summary.addEventListener("click", (event) => {
      event.stopPropagation();
      setSelectedPath(path);
    });

    details.appendChild(summary);

    const children = document.createElement("div");
    children.className = "dump-children";

    for (const [childKey, childValue] of Object.entries(value)) {
      const childPath = path ? `${path}.${childKey}` : childKey;
      renderNode(children, childKey, childValue, childPath, depth + 1);
    }

    details.appendChild(children);
    container.appendChild(details);
    return;
  }

  if (Array.isArray(value)) {
    const details = document.createElement("details");
    details.className = "dump-branch dump-node";
    details.dataset.path = path;
    details.open = depth < 2;

    const summary = document.createElement("summary");
    const keySpan = document.createElement("span");
    keySpan.className = "dump-key";
    keySpan.textContent = key;

    const metaSpan = document.createElement("span");
    metaSpan.className = "dump-meta";
    metaSpan.textContent = `[${value.length}]`;

    summary.appendChild(keySpan);
    summary.appendChild(metaSpan);
    summary.addEventListener("click", (event) => {
      event.stopPropagation();
      setSelectedPath(path);
    });

    details.appendChild(summary);

    const children = document.createElement("div");
    children.className = "dump-children";

    value.forEach((childValue, index) => {
      const childKey = `[${index}]`;
      const childPath = `${path}[${index}]`;
      renderNode(children, childKey, childValue, childPath, depth + 1);
    });

    details.appendChild(children);
    container.appendChild(details);
    return;
  }

  const row = document.createElement("div");
  row.className = "dump-leaf dump-node";
  row.dataset.path = path;
  row.addEventListener("click", (event) => {
    event.stopPropagation();
    setSelectedPath(path);
  });

  const keySpan = document.createElement("span");
  keySpan.className = "dump-key";
  keySpan.textContent = key;

  const valSpan = document.createElement("code");
  valSpan.className = "value";
  const text = formatScalar(value);
  valSpan.textContent = text.length > 600 ? `${text.slice(0, 600)}...` : text;
  if (text.length > 600) {
    valSpan.title = text;
  }

  row.appendChild(keySpan);
  row.appendChild(valSpan);
  container.appendChild(row);
}

function renderDump() {
  dumpEl.innerHTML = "";

  if (!state.result || !state.result.dump) {
    dumpEl.textContent = "No dump yet.";
    return;
  }

  const root = state.result.dump;
  for (const [key, value] of Object.entries(root)) {
    renderNode(dumpEl, key, value, key, 0);
  }

  applyDumpHighlighting();
}

function renderPathInfo() {
  pathInfoEl.innerHTML = "";
  const path = state.selectedPath;
  const checks = state.result ? state.result.checks || [] : [];

  if (!path) {
    pathInfoEl.className = "path-info";
    pathInfoEl.textContent = "No dump path selected.";
    return;
  }

  const related = checks.filter((check) => {
    const refs = Array.isArray(check.refs) ? check.refs : [];
    return refs.some((ref) => pathIntersects(path, ref));
  });

  pathInfoEl.className = "path-info active";

  const line = document.createElement("div");
  line.innerHTML = `Selected path: <span class="path">${path}</span>`;
  pathInfoEl.appendChild(line);

  if (related.length === 0) {
    const none = document.createElement("div");
    none.textContent = "No checks reference this path.";
    pathInfoEl.appendChild(none);
    return;
  }

  const relLine = document.createElement("div");
  relLine.textContent = "Referenced by:";
  pathInfoEl.appendChild(relLine);

  const row = document.createElement("div");
  row.className = "path-checks";

  related.forEach((check) => {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.textContent = check.title;
    btn.addEventListener("click", () => {
      setActiveCheck(check.id, true, true);
    });
    row.appendChild(btn);
  });

  pathInfoEl.appendChild(row);
}

function renderSummary() {
  summaryEl.innerHTML = "";
  if (!state.result) return;

  const summary = state.result.summary;
  const badges = [
    { label: `Overall: ${summary.overall.toUpperCase()}`, status: summary.overall, filter: false },
    { label: `Fail: ${summary.counts.fail}`, status: "fail", filter: true },
    { label: `Warn: ${summary.counts.warn}`, status: "warn", filter: true },
    { label: `Pass: ${summary.counts.pass}`, status: "pass", filter: true },
    { label: `Checks: ${summary.total}`, status: "", filter: false },
  ];

  badges.forEach((badge) => {
    if (badge.filter) {
      const btn = document.createElement("button");
      btn.type = "button";
      const active = state.statusFilters.has(badge.status);
      btn.className = `badge filter-toggle ${badge.status} ${active ? "on" : ""}`.trim();
      btn.textContent = badge.label;
      btn.title = active ? `Hide ${badge.status} checks` : `Show only/also ${badge.status} checks`;
      btn.addEventListener("click", () => {
        toggleStatusFilter(badge.status);
      });
      summaryEl.appendChild(btn);
      return;
    }

    const span = document.createElement("span");
    span.className = `badge ${badge.status}`.trim();
    span.textContent = badge.label;
    summaryEl.appendChild(span);
  });
}

function renderChecks() {
  checksEl.innerHTML = "";

  if (!state.result) {
    checksEl.textContent = "No checks yet.";
    return;
  }

  ensureActiveCheckVisible();
  const checks = getVisibleChecks();
  if (checks.length === 0) {
    checksEl.textContent = "No checks match current filters.";
    applyDumpHighlighting();
    renderPathInfo();
    return;
  }

  checks.forEach((check) => {
    const card = document.createElement("article");
    card.className = `check-card ${check.status}`;
    card.dataset.checkId = check.id;
    if (check.id === state.activeCheckId) {
      card.classList.add("active");
    }

    card.addEventListener("click", (event) => {
      if (event.target.closest("button")) {
        return;
      }
      setActiveCheck(check.id);
    });

    const title = document.createElement("div");
    title.className = "check-title";

    const icon = document.createElement("span");
    icon.className = `icon ${check.status}`;
    icon.textContent = statusIcon(check.status);

    const text = document.createElement("span");
    text.textContent = check.title;

    title.appendChild(icon);
    title.appendChild(text);
    card.appendChild(title);

    const desc = document.createElement("p");
    desc.className = "check-desc";
    desc.textContent = check.description;
    card.appendChild(desc);

    if (Array.isArray(check.evidence) && check.evidence.length > 0) {
      const evBox = document.createElement("div");
      evBox.className = "evidence";

      check.evidence.forEach((ev) => {
        const row = document.createElement("div");
        row.className = "evidence-item";

        const label = document.createElement("span");
        label.className = "label";
        label.textContent = ev.label || "evidence";

        const value = document.createElement("code");
        value.textContent = String(ev.value ?? "");

        row.appendChild(label);
        row.appendChild(value);

        if (ev.ref) {
          const refBtn = document.createElement("button");
          refBtn.type = "button";
          refBtn.className = "ref-btn";
          refBtn.textContent = `↳ ${ev.ref}`;
          refBtn.addEventListener("click", (event) => {
            event.stopPropagation();
            setActiveCheck(check.id, false, false, false);
            setSelectedPath(ev.ref);
            scrollToPath(ev.ref);
          });
          row.appendChild(refBtn);
        }

        evBox.appendChild(row);
      });

      card.appendChild(evBox);
    }

    if (Array.isArray(check.refs) && check.refs.length > 0) {
      const refs = document.createElement("div");
      refs.className = "refs";

      check.refs.forEach((refPath) => {
        const btn = document.createElement("button");
        btn.type = "button";
        btn.className = "ref-btn";
        btn.textContent = refPath;
        btn.addEventListener("click", (event) => {
          event.stopPropagation();
          setActiveCheck(check.id, false, false, false);
          setSelectedPath(refPath);
          scrollToPath(refPath);
        });
        refs.appendChild(btn);
      });

      card.appendChild(refs);
    }

    checksEl.appendChild(card);
  });

  applyDumpHighlighting();
  renderPathInfo();
}

function setResult(result) {
  state.result = result;

  const checks = getSortedChecks();
  if (checks.length === 0) {
    state.activeCheckId = null;
  } else {
    const firstFail = checks.find((c) => c.status === "fail");
    state.activeCheckId = firstFail ? firstFail.id : checks[0].id;
  }

  state.selectedPath = null;

  renderSummary();
  renderChecks();
  renderDump();
  renderPathInfo();
}

async function runVerification() {
  const input = inputEl.value;
  if (!input.trim()) {
    setStatus("Paste quote JSON or quote hex before verifying.", true);
    return;
  }

  runBtnEl.disabled = true;
  setStatus("Verifying...");

  try {
    const resp = await fetch("/api/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        input,
        online: onlineToggleEl.checked,
        intel_api_key: apiKeyEl.value,
        intel_base_url: baseUrlEl.value,
      }),
    });

    const data = await resp.json();
    if (!resp.ok) {
      throw new Error(data.error || "Verification failed");
    }
    if (data.error) {
      throw new Error(data.error);
    }

    setResult(data);
    setStatus(`Done. ${data.summary.counts.pass} pass, ${data.summary.counts.warn} warn, ${data.summary.counts.fail} fail.`);
  } catch (error) {
    setStatus(String(error), true);
    setResult({ summary: { overall: "fail", counts: { pass: 0, warn: 0, fail: 1 }, total: 1 }, checks: [], dump: {} });
  } finally {
    runBtnEl.disabled = false;
  }
}

async function loadExample(name) {
  try {
    const resp = await fetch(`/examples/${name}`);
    if (!resp.ok) {
      throw new Error(`Failed to load ${name}`);
    }
    const text = await resp.text();
    inputEl.value = text;
    setStatus(`Loaded ${name}.`);
  } catch (error) {
    setStatus(String(error), true);
  }
}

runBtnEl.addEventListener("click", runVerification);
example1Btn.addEventListener("click", () => loadExample("bad-quote-example.json"));
example2Btn.addEventListener("click", () => loadExample("good-quote-example.json"));

window.addEventListener("DOMContentLoaded", () => {
  setStatus("Ready.");
});
