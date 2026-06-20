const targetInput = document.getElementById("target");
const resultEl = document.getElementById("result");
const mapEl = document.getElementById("map");
const buttons = document.querySelectorAll(".buttons button");
let traceMap = null, traceToken = 0;

const TITLES = {
  ping: "Ping", traceroute: "Traceroute", port: "Scan de ports",
  whois: "Whois", dns: "DNS", ssl: "Certificat SSL/TLS", http: "Test HTTP",
};

const esc = (s) => String(s == null ? "" : s).replace(/[&<>"]/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));

// Real flag images (work on every OS, unlike emoji on Windows)
function flag(cc) {
  if (!cc || cc.length !== 2) return "";
  return `<img class="flag" src="https://flagcdn.com/${cc.toLowerCase()}.svg" alt="${esc(cc)}" title="${esc(cc)}">`;
}

const dnsTypesEl = document.getElementById("dnsTypes");
const dnsTypeButtons = dnsTypesEl.querySelectorAll("button");

buttons.forEach((b) => b.addEventListener("click", () => {
  // Show the DNS type selector only for the DNS tool
  dnsTypesEl.classList.toggle("hidden", b.dataset.tool !== "dns");
  if (b.dataset.tool === "dns") {
    dnsTypeButtons.forEach((x) => x.classList.toggle("active", x.dataset.rtype === "ALL"));
    run("dns", "ALL");
  } else {
    run(b.dataset.tool);
  }
}));

dnsTypeButtons.forEach((b) => b.addEventListener("click", () => {
  dnsTypeButtons.forEach((x) => x.classList.remove("active"));
  b.classList.add("active");
  run("dns", b.dataset.rtype);
}));

targetInput.addEventListener("keydown", (e) => { if (e.key === "Enter") run("ping"); });

async function run(tool, rtype) {
  const target = targetInput.value.trim();
  if (!target) { targetInput.focus(); return error("Entrez d'abord un domaine ou une IP."); }

  buttons.forEach((b) => { b.disabled = true; b.classList.toggle("active", b.dataset.tool === tool); });
  mapEl.classList.add("hidden");
  traceToken++; // stop any running traceroute animation
  resultEl.innerHTML = `<div class="loading"><span class="spinner"></span> ${TITLES[tool]} en cours…</div>`;

  const payload = { target };
  if (tool === "dns" && rtype) payload.rtype = rtype;

  try {
    const res = await fetch("/api/" + tool, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const d = await res.json();
    // ssl/http handle their own partial errors; everything else: stop here
    if (d.error && tool !== "ssl" && tool !== "http") return error(d.error);
    title(tool, target);
    ({ ping: showPing, traceroute: showTrace, port: showPort, whois: showWhois,
       dns: showDns, ssl: showSsl, http: showHttp }[tool])(d);
  } catch (e) {
    error("Impossible de contacter le serveur. Est-il bien lancé ?");
  } finally {
    buttons.forEach((b) => { b.disabled = false; });
  }
}

function error(msg) {
  buttons.forEach((b) => b.classList.remove("active"));
  resultEl.innerHTML = `<div class="error">⚠ ${esc(msg)}</div>`;
}
function title(tool, target) {
  resultEl.innerHTML = `<div class="result-title">${TITLES[tool]}<span class="target">${esc(target)}</span></div>`;
}
const add = (html) => { resultEl.innerHTML += html; };
const raw = (r) => r ? `<details><summary>Voir le détail brut</summary><div class="raw">${esc(r.trim())}</div></details>` : "";

/* ---- Ping ---- */
function showPing(d) {
  const loss = d.loss;
  add(`<div class="stats">
    <div class="stat"><div class="label">Latence moyenne</div><div class="value ${d.avg_ms != null ? "ok" : "bad"}">${d.avg_ms != null ? d.avg_ms + " ms" : "—"}</div></div>
    <div class="stat"><div class="label">Perte de paquets</div><div class="value ${loss === 0 ? "ok" : loss === 100 ? "bad" : "warn"}">${loss != null ? loss + " %" : "—"}</div></div>
    <div class="stat"><div class="label">État</div><div class="value ${loss === 100 ? "bad" : "ok"}">${loss === 100 ? "Inaccessible" : "Accessible"}</div></div>
  </div>` + raw(d.raw));
}

/* ---- Traceroute (animated map top-right + flags + table) ---- */
function showTrace(d) {
  const hops = d.hops || [];
  const pts = hops.filter((h) => h.lat != null && h.lon != null);
  const path = [];
  hops.forEach((h) => {
    if (h.countryCode && (!path.length || path[path.length - 1].cc !== h.countryCode))
      path.push({ cc: h.countryCode, name: h.country });
  });

  // Top zone: summary on the left, animated "radar" map on the right
  add(`<div class="trace-top">
    <div class="trace-summary">
      <div class="stat"><div class="label">Sauts</div><div class="value">${hops.length}</div></div>
      ${path.length ? `<div class="trace-flags"><div class="label" style="margin-bottom:7px">Pays traversés</div>${path.map((p) => `<div class="step">${flag(p.cc)} ${esc(p.name)}</div>`).join("")}</div>` : ""}
    </div>
    ${pts.length
      ? `<div id="traceMap" class="trace-map"></div>`
      : `<div class="trace-map trace-map-empty">Géolocalisation indisponible<br>(sauts privés uniquement)</div>`}
  </div>`);

  const rows = hops.map((h) => {
    const loc = h.country
      ? `${h.countryCode ? flag(h.countryCode) + " " : ""}${esc(h.country)}${h.city ? " · " + esc(h.city) : ""}`
      : '<span style="color:#9ca3af">—</span>';
    return `<tr><td class="mono">${h.hop}</td><td class="mono">${h.ip ? esc(h.ip) : "*"}</td>
      <td>${loc}</td><td class="mono">${h.rtt_ms != null ? h.rtt_ms + " ms" : "—"}</td></tr>`;
  }).join("");
  add(`<div class="table-wrap"><table><thead><tr><th>#</th><th>IP</th><th>Pays / Ville</th><th>Temps</th></tr></thead><tbody>${rows}</tbody></table></div>` + raw(d.raw));

  if (pts.length) animateTrace(pts);
}

function animateTrace(pts) {
  const el = document.getElementById("traceMap");
  if (!el || !window.L) return;
  const myToken = ++traceToken;
  if (traceMap) { try { traceMap.remove(); } catch (e) {} traceMap = null; }

  const map = L.map(el, { attributionControl: false, zoomControl: true });
  traceMap = map;
  L.tileLayer("https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png", { maxZoom: 19 }).addTo(map);

  const latlngs = pts.map((h) => [h.lat, h.lon]);
  map.fitBounds(L.latLngBounds(latlngs).pad(0.3));
  setTimeout(() => map.invalidateSize(), 150);

  // hop dots (revealed as the packet reaches them)
  const dots = latlngs.map((ll, i) => L.circleMarker(ll, {
    radius: i === latlngs.length - 1 ? 6 : 4, color: "#7dd3fc", weight: 2,
    fillColor: i === latlngs.length - 1 ? "#22c55e" : "#38bdf8", fillOpacity: 0.9, opacity: 0,
  }).addTo(map).bindPopup(
    `<div class="hop-popup"><b>Hop ${pts[i].hop}</b><br>${esc(pts[i].ip)}<br>${esc(pts[i].country || "")}${pts[i].city ? ", " + esc(pts[i].city) : ""}</div>`));

  const glow = L.polyline([], { color: "#38bdf8", weight: 10, opacity: 0.16 }).addTo(map);
  const trail = L.polyline([], { color: "#7dd3fc", weight: 3, opacity: 0.9 }).addTo(map);
  const halo = L.circleMarker(latlngs[0], { radius: 13, stroke: false, fillColor: "#fbbf24", fillOpacity: 0.25 }).addTo(map);
  const packet = L.circleMarker(latlngs[0], { radius: 5, color: "#fff", weight: 2, fillColor: "#fbbf24", fillOpacity: 1 }).addTo(map);

  function play() {
    if (myToken !== traceToken) return;
    let seg = 0;
    const trailPts = [latlngs[0]];
    trail.setLatLngs([]); glow.setLatLngs([]);
    dots.forEach((dm, i) => dm.setStyle({ opacity: i === 0 ? 1 : 0 }));
    packet.setLatLng(latlngs[0]); halo.setLatLng(latlngs[0]);

    function segment() {
      if (myToken !== traceToken) return;
      if (seg >= latlngs.length - 1) { setTimeout(play, 1800); return; } // loop
      const a = latlngs[seg], b = latlngs[seg + 1], dur = 650, t0 = performance.now();
      (function frame(now) {
        if (myToken !== traceToken) return;
        const t = Math.min(1, (now - t0) / dur);
        const ll = [a[0] + (b[0] - a[0]) * t, a[1] + (b[1] - a[1]) * t];
        packet.setLatLng(ll); halo.setLatLng(ll);
        const cur = [...trailPts, ll];
        trail.setLatLngs(cur); glow.setLatLngs(cur);
        if (t < 1) requestAnimationFrame(frame);
        else { trailPts.push(b); dots[seg + 1].setStyle({ opacity: 1 }); seg++; segment(); }
      })(performance.now());
    }
    setTimeout(segment, 350);
  }
  setTimeout(play, 400);
}

/* ---- Ports ---- */
function showPort(d) {
  const results = d.results || [];
  const open = results.filter((r) => r.open).length;
  const rows = results.map((r) => `<tr><td class="mono">${r.port}</td><td>${esc(r.service || "—")}</td>
    <td><span class="pill ${r.open ? "open" : "closed"}">${r.open ? "OUVERT" : "fermé"}</span></td></tr>`).join("");
  add(`<div class="stats">
    <div class="stat"><div class="label">IP résolue</div><div class="value mono">${esc(d.ip || "—")}</div></div>
    <div class="stat"><div class="label">Ports ouverts</div><div class="value ${open ? "ok" : ""}">${open}/${results.length}</div></div>
  </div><table><thead><tr><th>Port</th><th>Service</th><th>État</th></tr></thead><tbody>${rows}</tbody></table>`);
}

/* ---- Whois ---- */
function showWhois(d) {
  const f = d.fields || {};
  const labels = { "Domain Name": "Domaine", Registrar: "Registrar", "Creation Date": "Création",
    "Registry Expiry Date": "Expiration", "Updated Date": "Mise à jour",
    "Registrant Organization": "Organisation", "Registrant Country": "Pays", "Name Server": "Serveur DNS" };
  const kv = Object.keys(labels).filter((k) => f[k]).map((k) => `<div class="k">${labels[k]}</div><div class="v">${esc(f[k])}</div>`).join("");
  add((kv ? `<div class="kv">${kv}</div>` : `<p style="color:#6b7280">Pas de champs structurés — voir le brut.</p>`) + raw(d.raw));
}

/* ---- DNS ---- */
function showDns(d) {
  const rec = d.records || {};
  const types = Object.keys(rec);
  if (!types.length) return add(`<div class="error">Aucun enregistrement DNS trouvé.</div>`);
  add(types.map((t) => `<div class="dns-group"><span class="dns-type">${t}</span>
    ${rec[t].length
      ? rec[t].map((v) => `<div class="dns-val">${esc(v)}</div>`).join("")
      : `<div class="dns-val" style="color:#9ca3af">Aucun enregistrement ${t}.</div>`}</div>`).join(""));
}

/* ---- SSL ---- */
function showSsl(d) {
  if (d.error && d.valid === undefined && !d.notAfter) return error(d.error);
  const days = d.days_left;
  const cls = days == null ? "" : days < 0 ? "bad" : days < 21 ? "warn" : "ok";
  const badge = d.valid === false ? `<span class="pill closed">INVALIDE</span>` : `<span class="pill open">VALIDE</span>`;
  const kv = [["Domaine (CN)", d.subject], ["Émetteur", d.issuer], ["Émis le", d.notBefore],
    ["Expire le", d.notAfter], ["Protocole", d.protocol], ["Chiffrement", d.cipher],
    ["SAN", (d.san || []).join(", ")]].filter(([, v]) => v)
    .map(([k, v]) => `<div class="k">${k}</div><div class="v">${esc(v)}</div>`).join("");
  add(`<div class="stats">
    <div class="stat"><div class="label">Validité</div><div class="value">${badge}</div></div>
    <div class="stat"><div class="label">Expire dans</div><div class="value ${cls}">${days != null ? days + " j" : "—"}</div></div>
  </div>` + (d.error ? `<div class="error" style="margin-bottom:16px">⚠ ${esc(d.error)}</div>` : "") + `<div class="kv">${kv}</div>`);
}

/* ---- HTTP ---- */
function showHttp(d) {
  const chain = d.chain || [];
  if (!chain.length) return error(d.error || "Aucune réponse HTTP.");
  const f = d.final || chain[chain.length - 1];
  const cls = f.status < 300 ? "ok" : f.status < 400 ? "warn" : "bad";
  const kv = [["Code", `${f.status} ${f.reason || ""}`], ["Serveur", f.server],
    ["Type de contenu", f.content_type]].filter(([, v]) => v)
    .map(([k, v]) => `<div class="k">${k}</div><div class="v">${esc(v)}</div>`).join("");
  const rows = chain.length > 1 ? `<table style="margin-top:14px"><thead><tr><th>Code</th><th>URL</th><th>Temps</th></tr></thead><tbody>` +
    chain.map((c) => `<tr><td class="mono">${c.status}</td><td class="mono" style="word-break:break-all">${esc(c.url)}</td><td class="mono">${c.ms} ms</td></tr>`).join("") + `</tbody></table>` : "";
  add(`<div class="stats">
    <div class="stat"><div class="label">Statut</div><div class="value ${cls}">${f.status}</div></div>
    <div class="stat"><div class="label">Temps</div><div class="value">${f.ms} ms</div></div>
    <div class="stat"><div class="label">Redirections</div><div class="value">${chain.length - 1}</div></div>
  </div><div class="kv">${kv}</div>${rows}`);
}
