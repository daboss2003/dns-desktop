// The interface. No framework and no build step: this is a few screens, and a
// dependency here would be larger than the thing it renders.
//
// The credential comes from the shell, which injects it before this file runs.
// It is never in the URL and never in a cookie: a cookie on 127.0.0.1 is sent
// to every other service on 127.0.0.1 whatever port it listens on, and a token
// in a URL ends up in history and in a process's command line.
const TOKEN = (() => {
  if (window.__GATEWAYDNS_TOKEN__) return window.__GATEWAYDNS_TOKEN__;
  // Fallback for a browser rather than the application's own window. The
  // credential arrives in the fragment, which — unlike a query string — is
  // never sent to a server and never appears in a Referer. It is removed from
  // the address bar immediately so it does not linger in history or in a
  // screenshot.
  const m = /(?:^|[#&])t=([0-9a-f]+)/.exec(location.hash);
  if (!m) return "";
  history.replaceState(null, "", location.pathname);
  return m[1];
})();

async function api(path, opts = {}) {
  const res = await fetch(path, {
    ...opts,
    headers: { "Authorization": "Bearer " + TOKEN, "Content-Type": "application/json", ...(opts.headers || {}) },
  });
  if (!res.ok) {
    let msg = res.statusText;
    try { msg = (await res.json()).error || msg; } catch {}
    throw new Error(msg);
  }
  return res.status === 204 ? null : res.json();
}

// Every string from the network is set as text, never as markup. A device name
// is chosen by whoever owns the device, which on this network is not
// necessarily somebody trustworthy.
const el = (tag, text, cls) => {
  const n = document.createElement(tag);
  if (text !== undefined && text !== null) n.textContent = String(text);
  if (cls) n.className = cls;
  return n;
};
const $ = (id) => document.getElementById(id);

const nf = new Intl.NumberFormat();
function duration(ns) {
  const s = Math.floor(ns / 1e9);
  if (s < 60) return s + "s";
  if (s < 3600) return Math.floor(s / 60) + "m";
  if (s < 86400) return Math.floor(s / 3600) + "h " + Math.floor((s % 3600) / 60) + "m";
  return Math.floor(s / 86400) + "d " + Math.floor((s % 86400) / 3600) + "h";
}
function ago(iso) {
  const then = new Date(iso).getTime();
  if (!then || then < 0) return "—";
  const s = Math.max(0, Math.floor((Date.now() - then) / 1000));
  if (s < 45) return "just now";
  if (s < 3600) return Math.floor(s / 60) + "m ago";
  if (s < 86400) return Math.floor(s / 3600) + "h ago";
  return Math.floor(s / 86400) + "d ago";
}
const clock = (iso) => new Date(iso).toLocaleTimeString();

let view = "overview";
let blockedFilter = "";

document.querySelectorAll(".tab").forEach((b) => {
  b.onclick = () => {
    document.querySelectorAll(".tab").forEach((x) => x.classList.toggle("active", x === b));
    document.querySelectorAll(".view").forEach((v) => v.classList.add("hidden"));
    view = b.dataset.view;
    $(view).classList.remove("hidden");
    refresh();
  };
});
document.querySelectorAll(".chip").forEach((c) => {
  c.onclick = () => {
    document.querySelectorAll(".chip").forEach((x) => x.classList.toggle("active", x === c));
    blockedFilter = c.dataset.blocked;
    loadQueries();
  };
});

async function loadStatus() {
  const s = await api("/api/status");
  $("dot").className = "dot " + (s.serving ? "on" : "off");
  $("build").textContent = s.build.version === "unknown" ? "" : s.build.version;
  $("s-queries").textContent = nf.format(s.queries);
  $("s-blocked").textContent = nf.format(s.blocked);
  $("s-cache").textContent = nf.format(s.cache_hits);
  $("s-devices").textContent = nf.format(s.devices);
  $("s-listen").textContent = s.listen + (s.serving ? "" : " (not serving)");
  $("s-upstreams").textContent = s.upstreams.join(", ");
  $("s-rules").textContent = nf.format(s.block_rules) + " blocking, " + nf.format(s.allow_rules) + " allowing";
  $("s-uptime").textContent = s.serving ? duration(s.uptime_ns) : "—";
  $("s-block-rules").textContent = nf.format(s.block_rules);
  $("s-allow-rules").textContent = nf.format(s.allow_rules);

  // The single most useful sentence on this screen: what to actually type into
  // a router or a phone. Loopback is excluded, because telling somebody to
  // point a phone at 127.0.0.1 is the commonest way this is misconfigured.
  const port = s.listen.split(":").pop();
  const hint = $("point-hint");
  hint.textContent = s.local_addrs.length
    ? "Point a device's DNS server at " + s.local_addrs[0] +
      (port === "53" ? "" : " port " + port) + " and it is filtered."
    : "This machine has no address on a local network yet, so no other device can reach it.";

  $("s-platform").textContent = "Detected platform: " + s.platform + ".";
  const caps = $("s-caps");
  caps.replaceChildren();
  for (const c of s.capabilities.capabilities) {
    const li = el("li");
    li.append(el("span", c.name, "n"));
    li.append(el("span", c.available ? "available" : "unavailable", c.available ? "y" : "x"));
    if (!c.available && c.reason) li.append(el("span", c.reason, "muted"));
    caps.append(li);
  }
}

async function loadDevices() {
  const list = await api("/api/devices");
  const body = document.querySelector("#device-table tbody");
  body.replaceChildren();
  $("devices-empty").style.display = list.length ? "none" : "";
  document.querySelector("#device-table").style.display = list.length ? "" : "none";

  for (const d of list) {
    const tr = el("tr");

    const nameCell = el("td");
    const wrap = el("div", null, "name-cell");
    const input = document.createElement("input");
    input.value = d.name || "";
    input.placeholder = d.hostname || (d.addrs && d.addrs[0]) || "unnamed";
    input.onchange = async () => {
      try {
        await api("/api/devices/" + encodeURIComponent(d.id) + "/name", {
          method: "POST", body: JSON.stringify({ name: input.value }),
        });
      } catch (e) { alert("Could not rename: " + e.message); }
    };
    wrap.append(input);
    if (d.paused) wrap.append(el("span", "paused", "pill paused"));
    nameCell.append(wrap);
    tr.append(nameCell);

    tr.append(el("td", (d.addrs || []).join(", ") || "—"));
    tr.append(el("td", d.hwaddr || "—"));
    tr.append(el("td", ago(d.last_seen)));

    const actions = el("td");
    const pause = el("button", d.paused ? "Resume" : "Pause", "link");
    pause.onclick = async () => {
      try {
        await api("/api/devices/" + encodeURIComponent(d.id) + "/pause", {
          method: "POST", body: JSON.stringify({ paused: !d.paused }),
        });
        loadDevices();
      } catch (e) { alert("Could not change: " + e.message); }
    };
    const forget = el("button", "Forget", "link danger");
    forget.onclick = async () => {
      if (!confirm("Forget this device? Its name and its rules go with it.")) return;
      try {
        await api("/api/devices/" + encodeURIComponent(d.id), { method: "DELETE" });
        loadDevices();
      } catch (e) { alert("Could not forget: " + e.message); }
    };
    actions.append(pause, forget);
    tr.append(actions);
    body.append(tr);
  }
}

async function loadQueries() {
  const body = document.querySelector("#query-table tbody");
  const empty = $("queries-empty");
  let list;
  try {
    const q = blockedFilter === "" ? "" : "?blocked=" + blockedFilter;
    list = await api("/api/queries" + q);
  } catch (e) {
    body.replaceChildren();
    document.querySelector("#query-table").style.display = "none";
    empty.style.display = "";
    empty.textContent = e.message;
    return;
  }
  body.replaceChildren();
  document.querySelector("#query-table").style.display = list.length ? "" : "none";
  empty.style.display = list.length ? "none" : "";
  empty.textContent = "Nothing yet.";
  for (const q of list) {
    const tr = el("tr");
    tr.append(el("td", clock(q.at)));
    tr.append(el("td", q.device || q.client || "—"));
    tr.append(el("td", q.name));
    tr.append(el("td", q.type));
    const answer = el("td");
    answer.append(el("span", q.blocked ? "blocked" : q.rcode, q.blocked ? "pill blocked" : "pill"));
    tr.append(answer);
    body.append(tr);
  }
}

$("rule-form").onsubmit = (e) => { e.preventDefault(); addRule("block"); };
$("allow-btn").onclick = () => addRule("allow");
async function addRule(kind) {
  const name = $("rule-name").value.trim();
  const msg = $("rule-msg");
  if (!name) return;
  try {
    await api("/api/rules/" + kind, { method: "POST", body: JSON.stringify({ name }) });
    msg.className = "hint good";
    msg.textContent = (kind === "block" ? "Blocking " : "Allowing ") + name + " and everything under it.";
    $("rule-name").value = "";
    loadStatus();
  } catch (e) {
    msg.className = "hint bad";
    msg.textContent = e.message;
  }
}
$("flush").onclick = async () => {
  try {
    await api("/api/cache/flush", { method: "POST" });
    $("rule-msg").className = "hint good";
    $("rule-msg").textContent = "Cache cleared. Every name is looked up fresh.";
  } catch (e) { alert(e.message); }
};

async function refresh() {
  try {
    await loadStatus();
    if (view === "devices") await loadDevices();
    if (view === "activity") await loadQueries();
  } catch (e) {
    $("dot").className = "dot off";
    console.error(e);
  }
}
refresh();
// Polling rather than a stream, for now. A filtering resolver's dashboard is
// looked at rarely and briefly, and two seconds of staleness costs nothing
// against a connection to keep alive and reconnect.
setInterval(refresh, 2000);
