// soc-shark · GUI (ADR-013).
//
// Regla de oro: TODO dato que viene de la captura (dominios, rutas, nombres
// de archivo…) lo controla quien genera el tráfico. Se pinta siempre como
// texto (textContent / nodos de texto), nunca con innerHTML.
"use strict";

(() => {
  const TOKEN = document.querySelector('meta[name="socshark-token"]').content;
  const $ = (sel) => document.querySelector(sel);

  // ------------------------------------------------------------ DOM seguro

  /** Crea un elemento; los hijos de tipo texto se insertan como texto. */
  function h(tag, attrs, ...kids) {
    const el = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v == null || v === false) continue;
      if (k === "class") el.className = v;
      else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
      else el.setAttribute(k, v === true ? "" : String(v));
    }
    for (const kid of kids.flat(Infinity)) {
      if (kid == null || kid === false) continue;
      el.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
    }
    return el;
  }

  function clear(el) {
    while (el.firstChild) el.removeChild(el.firstChild);
    return el;
  }

  // ------------------------------------------------------------ API

  async function api(path, opts = {}) {
    const res = await fetch(path, {
      ...opts,
      headers: { "X-Socshark-Token": TOKEN, ...(opts.headers || {}) },
    });
    let body = null;
    try {
      body = await res.json();
    } catch {
      /* respuesta sin JSON */
    }
    if (!res.ok) {
      const err = new Error((body && body.error) || `Error ${res.status}`);
      err.status = res.status;
      err.body = body;
      throw err;
    }
    return body;
  }

  // ------------------------------------------------------------ estado

  const state = {
    session: null,
    flows: [], // [{idx, flow, explain}]
    byIdx: new Map(),
    stories: [],
    mode: "simple",
    view: "todo",
    showNoise: false,
    sort: "time",
    storyFilter: null, // {title, idx: Set}
    selected: null,
    tab: "explain",
    packetCache: new Map(),
    packetSel: null,
  };

  function pref(key, value) {
    try {
      if (value === undefined) return localStorage.getItem("socshark." + key);
      localStorage.setItem("socshark." + key, value);
    } catch {
      /* almacenamiento no disponible: se usan los valores por defecto */
    }
    return null;
  }

  // ------------------------------------------------------------ formato

  const LEVEL = {
    ok: { icon: "✓", label: "Normal" },
    raro: { icon: "!", label: "Raro" },
    peligro: { icon: "✕", label: "Peligro" },
  };
  const RANK = { ok: 0, raro: 1, peligro: 2 };
  const STATE_ES = { Active: "activa", Idle: "sin cerrar", Closed: "cerrada" };
  const nf = new Intl.NumberFormat("es-ES");

  function fmtBytes(n) {
    const units = ["B", "KB", "MB", "GB", "TB"];
    let v = n;
    let u = 0;
    while (v >= 1024 && u < units.length - 1) {
      v /= 1024;
      u++;
    }
    return u === 0 ? `${n} B` : `${v.toLocaleString("es-ES", { maximumFractionDigits: 1 })} ${units[u]}`;
  }
  const fmtTime = (us) => new Date(us / 1000).toLocaleTimeString("es-ES", { hour12: false });
  const fmtDateTime = (us) =>
    new Date(us / 1000).toLocaleString("es-ES", { dateStyle: "medium", timeStyle: "medium" });
  function fmtDuration(us) {
    const s = us / 1e6;
    if (s < 1) return `${(s * 1000).toLocaleString("es-ES", { maximumFractionDigits: 1 })} ms`;
    if (s < 120) return `${s.toLocaleString("es-ES", { maximumFractionDigits: 1 })} s`;
    const m = Math.floor(s / 60);
    if (m < 120) return `${m} min ${Math.round(s - m * 60)} s`;
    return `${Math.floor(m / 60)} h ${m % 60} min`;
  }
  const fmtRel = (us) =>
    "+" + (us / 1e6).toLocaleString("es-ES", { minimumFractionDigits: 3, maximumFractionDigits: 3 }) + " s";
  const endpoint = (ip, port) => (ip.includes(":") ? `[${ip}]:${port}` : `${ip}:${port}`);

  function dot(level) {
    const l = LEVEL[level] || LEVEL.ok;
    return h("span", { class: `dot ${level}`, title: l.label, "aria-label": l.label }, l.icon);
  }
  function badge(level) {
    const l = LEVEL[level] || LEVEL.ok;
    return h("span", { class: `badge ${level}` }, `${l.icon} ${l.label}`);
  }
  function mitreLink(id) {
    if (!id || !/^T\d{4}(\.\d{3})?$/.test(id)) return null;
    return h(
      "a",
      {
        class: "mitre",
        href: `https://attack.mitre.org/techniques/${id.replace(".", "/")}/`,
        target: "_blank",
        rel: "noopener noreferrer",
        title: "Técnica de ataque en MITRE ATT&CK (abre en el navegador)",
      },
      `MITRE ${id}`,
    );
  }

  // ------------------------------------------------------------ glosario

  const GLOSSARY = [
    ["DNS", "La «guía telefónica» de Internet: traduce nombres como google.com en direcciones IP."],
    ["IP", "La dirección de un equipo en la red, como la dirección postal de una casa."],
    ["IPv4", "La versión clásica de las direcciones IP (por ejemplo 192.168.1.10)."],
    ["IPv6", "La versión nueva de las direcciones IP, más largas (por ejemplo fd00::10)."],
    ["MAC", "La dirección física de una tarjeta de red. Solo sirve dentro de la red local."],
    ["TCP", "Forma de enviar datos con conexión: numera cada trozo y confirma que llega, en orden."],
    ["UDP", "Forma de enviar datos sin conexión ni confirmación: rápida, pero si algo se pierde no se reenvía."],
    ["TLS", "El cifrado que protege las conexiones (el candado del navegador)."],
    ["HTTPS", "Web cifrada: se sabe con qué web hablas, pero no qué ves ni envías."],
    ["HTTP", "Web sin cifrar: cualquiera en la red puede leer lo que se envía."],
    ["SSH", "Acceso remoto seguro (cifrado) para administrar equipos a distancia."],
    ["Telnet", "Acceso remoto antiguo y sin cifrar: usuario y contraseña viajan a la vista."],
    ["SMB", "El protocolo de las carpetas compartidas de Windows."],
    ["RDP", "Escritorio remoto de Windows."],
    ["NTP", "El protocolo con el que los equipos ponen su reloj en hora."],
    ["DHCP", "El servicio que reparte direcciones IP a los equipos que se conectan a la red."],
    ["mDNS", "Anuncios automáticos en la red local (impresoras, móviles, televisores…)."],
    ["SYN", "Primer paso de una conexión TCP: «¿hablamos?»."],
    ["ACK", "Confirmación TCP: «recibido»."],
    ["RST", "Corte brusco de una conexión TCP: «no, gracias» o «se acabó»."],
    ["FIN", "Cierre ordenado de una conexión TCP: «he terminado»."],
    ["TTL", "Saltos entre routers que le quedan a un paquete antes de descartarse."],
    ["JA4", "Huella del programa que abre una conexión cifrada; ayuda a reconocer el mismo software."],
    ["SNI", "El nombre de la web que el programa pide al abrir una conexión cifrada (va visible)."],
    ["SHA-256", "Huella única de un archivo: si dos archivos tienen la misma, son idénticos."],
    ["VirusTotal", "Servicio web gratuito que analiza archivos y huellas con decenas de antivirus."],
    ["nmap", "Programa muy conocido para escanear redes y buscar servicios abiertos."],
    ["Tor", "Red que oculta quién se comunica con quién haciendo rebotar el tráfico por varios equipos."],
    ["malware", "Programa malicioso: virus, troyanos, ransomware…"],
    ["puerto", "Número que indica a qué servicio va dirigida una conexión (443 = web segura, 22 = SSH…)."],
    ["puertos", "Números que indican a qué servicio va dirigida una conexión (443 = web segura, 22 = SSH…)."],
    ["paquete", "Cada trocito en que se divide la información que viaja por la red."],
    ["paquetes", "Los trocitos en que se divide la información que viaja por la red."],
    ["escaneo", "Probar muchos puertos o equipos para descubrir qué servicios hay abiertos."],
    ["cortafuegos", "Filtro que decide qué conexiones se permiten y cuáles se bloquean."],
    ["multicast", "Envío a un grupo de equipos a la vez en la red local."],
    ["difusión", "Envío a todos los equipos de la red local a la vez."],
  ];
  const DEFS = new Map(GLOSSARY.map(([t, d]) => [t.toLowerCase(), [t, d]]));
  const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  // Siglas exactas; palabras con la inicial en cualquier caja.
  const TERM_RE = new RegExp(
    "(?<![\\p{L}\\p{N}_-])(" +
      GLOSSARY.map(([t]) => t)
        .sort((a, b) => b.length - a.length)
        .map((t) => {
          const e = escapeRe(t);
          return t === t.toUpperCase() || /[A-Z]/.test(t.slice(1)) ? e : `[${t[0].toUpperCase()}${t[0]}]${escapeRe(t.slice(1))}`;
        })
        .join("|") +
      ")(?![\\p{L}\\p{N}_-])",
    "gu",
  );

  /** Texto con los términos del glosario marcados (la primera vez de cada uno). */
  function rich(value) {
    const text = String(value);
    const frag = document.createDocumentFragment();
    const seen = new Set();
    let last = 0;
    for (const m of text.matchAll(TERM_RE)) {
      const key = m[1].toLowerCase();
      if (seen.has(key) || !DEFS.has(key)) continue;
      seen.add(key);
      frag.append(text.slice(last, m.index));
      frag.append(h("span", { class: "term", tabindex: "0", "data-term": key }, m[1]));
      last = m.index + m[1].length;
    }
    frag.append(text.slice(last));
    return frag;
  }

  const tooltip = $("#tooltip");
  function showTip(target) {
    const def = DEFS.get(target.dataset.term);
    if (!def) return;
    clear(tooltip).append(h("b", null, def[0]), def[1]);
    tooltip.hidden = false;
    const r = target.getBoundingClientRect();
    const tw = tooltip.offsetWidth;
    const th = tooltip.offsetHeight;
    let x = Math.min(Math.max(8, r.left), window.innerWidth - tw - 8);
    let y = r.bottom + 6;
    if (y + th > window.innerHeight - 8) y = r.top - th - 6;
    tooltip.style.left = `${x}px`;
    tooltip.style.top = `${y}px`;
  }
  const hideTip = () => (tooltip.hidden = true);
  for (const ev of ["mouseover", "focusin"]) {
    document.addEventListener(ev, (e) => {
      const t = e.target.closest && e.target.closest(".term");
      if (t) showTip(t);
    });
  }
  for (const ev of ["mouseout", "focusout"]) {
    document.addEventListener(ev, (e) => {
      if (e.target.closest && e.target.closest(".term")) hideTip();
    });
  }
  document.addEventListener("scroll", hideTip, true);

  // ------------------------------------------------------------ avisos

  function toast(message, kind = "error") {
    const t = h("div", { class: `toast ${kind}`, role: "status" }, message);
    document.body.append(t);
    setTimeout(() => t.remove(), 7000);
    t.addEventListener("click", () => t.remove());
  }

  function busy(text) {
    $("#busy").hidden = !text;
    if (text) $("#busy-text").textContent = text;
  }

  // ------------------------------------------------------------ cabecera y resumen

  function renderHeader() {
    const info = clear($("#capture-info"));
    const s = state.session;
    if (!s || !s.loaded) return;
    info.append(h("b", null, s.name), ` · ${nf.format(s.packets)} paquetes`);
    if (s.first_seen) info.append(` · ${fmtDateTime(s.first_seen)}`);
    document.title = `${s.name} · soc-shark`;
  }

  function renderOverview() {
    const ov = clear($("#overview"));
    const s = state.session;
    if (!s || !s.loaded) return;
    const stat = (cls, n, label) =>
      h("div", { class: `stat ${cls}` }, h("span", { class: "n" }, nf.format(n)), h("span", { class: "l" }, label));
    ov.append(
      stat("peligro", s.levels.peligro, s.levels.peligro === 1 ? "peligro" : "peligros"),
      stat("raro", s.levels.raro, s.levels.raro === 1 ? "cosa rara" : "cosas raras"),
      stat("ok", s.levels.ok, "normales"),
    );
    const span = s.first_seen != null && s.last_seen != null ? s.last_seen - s.first_seen : 0;
    const dur = span > 0 ? ` · ${fmtDuration(span)} de tráfico` : "";
    const convs = s.flows === 1 ? "1 conversación" : `${nf.format(s.flows)} conversaciones`;
    ov.append(
      h(
        "div",
        { class: "meta" },
        `${convs} (${nf.format(s.noise)} de fondo)${dur}`,
        s.packets_truncated ? " · captura muy grande: algunos paquetes no muestran su contenido" : "",
      ),
    );
  }

  function renderStories() {
    const list = clear($("#stories"));
    if (!state.stories.length) {
      list.append(
        h(
          "li",
          { class: "all-good" },
          h("b", null, "✓ No hemos visto nada preocupante"),
          "Puedes revisar igualmente las conversaciones si buscas algo concreto.",
        ),
      );
      return;
    }
    for (const s of state.stories) {
      const n = s.flows.length;
      list.append(
        h(
          "li",
          { class: `story ${s.level}` },
          h("h3", null, dot(s.level), h("span", null, s.title)),
          h("p", null, rich(s.story)),
          h("p", { class: "todo" }, rich(s.action)),
          h(
            "div",
            { class: "actions" },
            h(
              "button",
              {
                class: "btn",
                type: "button",
                onclick: () => showStory(s),
              },
              n === 1 ? "Ver la conversación" : `Ver las ${n} conversaciones`,
            ),
            mitreLink(s.mitre),
          ),
        ),
      );
    }
  }

  function showStory(story) {
    state.storyFilter = { title: story.title, idx: new Set(story.flows) };
    // Una historia puede incluir tráfico de fondo o normal: se muestra todo.
    state.view = "todo";
    syncChips();
    renderStoryChip();
    renderTable();
    const first = visibleFlows()[0];
    if (first) select(first.idx);
  }

  function renderStoryChip() {
    const chip = $("#story-chip");
    clear(chip);
    chip.hidden = !state.storyFilter;
    if (!state.storyFilter) return;
    chip.append(
      `Mostrando: ${state.storyFilter.title}`,
      h(
        "button",
        {
          type: "button",
          title: "Ver todas las conversaciones",
          "aria-label": "Quitar",
          onclick: () => {
            state.storyFilter = null;
            renderStoryChip();
            renderTable();
          },
        },
        "✕",
      ),
    );
  }

  // ------------------------------------------------------------ tabla

  function visibleFlows() {
    let list = state.flows;
    if (state.storyFilter) list = list.filter((r) => state.storyFilter.idx.has(r.idx));
    else {
      if (!state.showNoise) list = list.filter((r) => !r.flow.is_background_noise);
      if (state.view === "importante") list = list.filter((r) => r.explain.level !== "ok");
    }
    const key = {
      time: (r) => r.flow.first_seen_micros,
      level: (r) => -(RANK[r.explain.level] * 1000 + r.flow.risk_score),
      bytes: (r) => -(r.flow.bytes + r.flow.bytes_rev),
    }[state.sort];
    return [...list].sort((a, b) => key(a) - key(b) || a.idx - b.idx);
  }

  function renderTable() {
    const head = clear($("#flows-head"));
    const body = clear($("#flows-body"));
    const expert = state.mode === "experto";
    const cols = expert
      ? ["", "Protocolo", "Origen", "Destino", "Paquetes", "Bytes", "Riesgo", "Alertas"]
      : ["", "Qué pasó", "Hora", "Datos"];
    head.append(h("tr", null, cols.map((c) => h("th", { scope: "col" }, c))));

    const rows = visibleFlows();
    const frag = document.createDocumentFragment();
    for (const r of rows) {
      const f = r.flow;
      const e = r.explain;
      const proto = f.l7_protocol !== "Unknown" ? f.l7_protocol.toUpperCase() : f.transport.toUpperCase();
      const cells = expert
        ? [
            h("td", null, dot(e.level)),
            h("td", { class: "mono" }, proto),
            h("td", { class: "mono" }, endpoint(f.src_ip, f.src_port)),
            h(
              "td",
              { class: "mono" },
              endpoint(f.dst_ip, f.dst_port),
              f.resolved_domain ? h("div", { class: "sub", title: f.resolved_domain }, f.resolved_domain) : null,
            ),
            h("td", { class: "num" }, nf.format(f.packets + f.packets_rev)),
            h("td", { class: "num" }, fmtBytes(f.bytes + f.bytes_rev)),
            h("td", { class: `num risk ${e.level}` }, f.risk_score),
            h("td", { class: "mono" }, f.alerts.map((a) => a.id).join(", ") || "—"),
          ]
        : [
            h("td", null, dot(e.level)),
            h(
              "td",
              null,
              h("div", { class: "headline" }, e.headline),
              h("div", { class: "sub mono" }, `${proto} · ${endpoint(f.src_ip, f.src_port)} → ${endpoint(f.dst_ip, f.dst_port)}`),
            ),
            h("td", { class: "time" }, fmtTime(f.first_seen_micros)),
            h("td", { class: "num" }, fmtBytes(f.bytes + f.bytes_rev)),
          ];
      const tr = h(
        "tr",
        {
          class: f.is_background_noise ? "noise" : null,
          "aria-selected": String(r.idx === state.selected),
          "data-idx": r.idx,
          tabindex: "-1",
          onclick: () => select(r.idx),
        },
        cells,
      );
      frag.append(tr);
    }
    body.append(frag);

    const total = state.flows.length;
    $("#flows-count").textContent = rows.length === total ? `(${nf.format(total)})` : `(${nf.format(rows.length)} de ${nf.format(total)})`;
    const empty = $("#flows-empty");
    empty.hidden = rows.length > 0;
    if (!rows.length) {
      empty.textContent =
        state.view === "importante" && !state.storyFilter
          ? "Nada importante con estos filtros. ¡Buena señal!"
          : "Ninguna conversación coincide con el filtro.";
    }
  }

  function select(idx, { focus = false } = {}) {
    state.selected = idx;
    state.packetSel = null;
    for (const tr of $("#flows-body").children) {
      const on = Number(tr.dataset.idx) === idx;
      tr.setAttribute("aria-selected", String(on));
      if (on) {
        tr.scrollIntoView({ block: "nearest" });
        if (focus) tr.focus({ preventScroll: true });
      }
    }
    renderDetail();
  }

  function moveSelection(delta) {
    const rows = visibleFlows();
    if (!rows.length) return;
    const pos = rows.findIndex((r) => r.idx === state.selected);
    const next = rows[Math.min(rows.length - 1, Math.max(0, pos < 0 ? 0 : pos + delta))];
    select(next.idx, { focus: true });
  }

  // ------------------------------------------------------------ detalle

  function setTab(tab) {
    state.tab = tab;
    for (const b of document.querySelectorAll(".tabs [role=tab]")) b.setAttribute("aria-selected", String(b.dataset.tab === tab));
    renderDetail();
  }

  function renderDetail() {
    const box = clear($("#detail"));
    const r = state.byIdx.get(state.selected);
    const pk = $("#tab-packets");
    if (!r) {
      pk.textContent = "Paquetes";
      box.append(h("p", { class: "placeholder" }, "Elige una conversación de la lista para ver qué pasó."));
      return;
    }
    pk.textContent = `Paquetes (${nf.format(r.flow.packets + r.flow.packets_rev)})`;
    if (state.tab === "explain") renderExplain(box, r);
    else if (state.tab === "packets") renderPackets(box, r);
    else box.append(h("pre", { class: "json" }, JSON.stringify(r.flow, null, 2)));
  }

  function renderExplain(box, r) {
    const f = r.flow;
    const e = r.explain;
    box.append(
      h("div", { class: "explain-head" }, dot(e.level), h("div", null, h("h2", null, e.title), h("div", { class: "sub" }, badge(e.level)))),
      h("p", { class: "lead" }, rich(e.story)),
    );
    for (const a of e.alerts) {
      box.append(
        h(
          "div",
          { class: `alert-card ${a.level}` },
          h("h3", null, dot(a.level), a.title, mitreLink(a.mitre)),
          h("p", null, rich(a.story)),
          h("div", { class: "todo" }, h("b", null, "Qué hacer"), rich(a.action)),
        ),
      );
    }

    const facts = [];
    const fact = (k, ...v) => facts.push(h("dt", null, k), h("dd", null, ...v));
    fact("Quién empezó", h("span", { class: "mono" }, endpoint(f.src_ip, f.src_port)));
    fact("Con quién", h("span", { class: "mono" }, endpoint(f.dst_ip, f.dst_port)), f.resolved_domain ? ` · ${f.resolved_domain}` : "");
    fact("Protocolo", rich(`${f.l7_protocol !== "Unknown" ? f.l7_protocol.toUpperCase() + " sobre " : ""}${f.transport.toUpperCase()}`));
    fact("Cuándo", `${fmtDateTime(f.first_seen_micros)} · duró ${fmtDuration(f.duration_micros)}`);
    fact(
      "Volumen",
      `ida: ${nf.format(f.packets)} paquetes (${fmtBytes(f.bytes)}) · vuelta: ${nf.format(f.packets_rev)} paquetes (${fmtBytes(f.bytes_rev)})`,
    );
    fact("Estado", STATE_ES[f.state] || f.state);
    if (f.tls_sni) fact(h("span", { class: "term", tabindex: "0", "data-term": "sni" }, "Web pedida (SNI)"), f.tls_sni);
    if (f.ja4_fingerprint) fact(h("span", { class: "term", tabindex: "0", "data-term": "ja4" }, "Huella JA4"), h("span", { class: "mono" }, f.ja4_fingerprint));
    for (const file of f.extracted_files || []) {
      fact(
        "Archivo",
        `${file.name} · ${fmtBytes(file.size)}${file.magic ? ` · tipo real: ${file.magic}` : ""}`,
        file.sha256 ? h("div", { class: "mono sub" }, `SHA-256 ${file.sha256}`) : null,
      );
    }
    if ((f.threat_intel || []).length) fact("Listas de amenazas", f.threat_intel.join(", "));
    fact("Riesgo", `${f.risk_score} / 100`);
    box.append(h("dl", { class: "facts" }, facts));
  }

  async function renderPackets(box, r) {
    let data = state.packetCache.get(r.idx);
    if (!data) {
      box.append(h("p", { class: "placeholder" }, "Cargando paquetes…"));
      try {
        data = await api(`/api/flows/${r.idx}/packets`);
      } catch (err) {
        clear(box).append(h("p", { class: "placeholder" }, `No se pudieron cargar los paquetes: ${err.message}`));
        return;
      }
      state.packetCache.set(r.idx, data);
      if (state.selected !== r.idx || state.tab !== "packets") return; // el usuario ya cambió
      clear(box);
    }
    if (!data.packets.length) {
      box.append(h("p", { class: "placeholder" }, "Esta conversación no tiene paquetes que mostrar."));
      return;
    }
    const side = h("div", { class: "pkt-side" });
    const tbody = h("tbody");
    const list = h(
      "div",
      { class: "pkt-list" },
      h("table", null, h("thead", null, h("tr", null, ["N.º", "Tiempo", "", "Tamaño", "Qué hace"].map((c) => h("th", null, c)))), tbody),
    );
    for (const p of data.packets) {
      tbody.append(
        h(
          "tr",
          {
            "data-n": p.n,
            "aria-selected": "false",
            onclick: () => pickPacket(p.n, tbody, side),
          },
          h("td", { class: "num" }, p.n),
          h("td", { class: "num" }, fmtRel(p.rel_micros)),
          h("td", { class: `dir ${p.outbound ? "out" : "in"}`, title: p.outbound ? "de quien empezó hacia el otro lado" : "respuesta" }, p.outbound ? "→" : "←"),
          h("td", { class: "num" }, fmtBytes(p.len)),
          h("td", null, p.summary),
        ),
      );
    }
    if (data.more) tbody.append(h("tr", null, h("td", { colspan: "5", class: "sub" }, "Solo se muestran los primeros 5.000 paquetes de esta conversación.")));
    box.append(h("div", { class: "packets" }, list, side));
    pickPacket(state.packetSel || data.packets[0].n, tbody, side);
  }

  async function pickPacket(n, tbody, side) {
    state.packetSel = n;
    for (const tr of tbody.children) tr.setAttribute("aria-selected", String(Number(tr.dataset.n) === n));
    let d;
    try {
      d = await api(`/api/packets/${n}`);
    } catch (err) {
      clear(side).append(h("p", { class: "placeholder" }, err.message));
      return;
    }
    if (state.packetSel !== n) return;
    clear(side);
    const layersBox = h("div", { class: "layers" });
    const hexBox = h("div", { class: "hex", "aria-label": "Bytes del paquete" });
    const spans = renderHex(hexBox, d.hex);
    const layerEls = [];
    const highlight = (range, hot) => {
      for (const s of spans) s.classList.remove("in-layer", "hot");
      if (!range) return;
      for (let i = range[0]; i < Math.min(range[1], spans.length / 2); i++) {
        spans[i].classList.add(hot ? "hot" : "in-layer");
        spans[i + spans.length / 2].classList.add(hot ? "hot" : "in-layer");
      }
    };
    d.layers.forEach((layer, i) => {
      const det = h(
        "details",
        { class: "layer", open: i === d.layers.length - 1 ? true : null },
        h("summary", null, h("b", null, layer.name), h("span", null, rich(layer.about))),
        h(
          "table",
          null,
          layer.fields.map((f) => h("tr", null, h("td", null, f.name), h("td", { class: "val" }, f.value), h("td", { class: "help" }, rich(f.help)))),
        ),
      );
      det.addEventListener("mouseenter", () => highlight(layer.range, true));
      det.addEventListener("mouseleave", () => highlight(null));
      det.addEventListener("toggle", () => det.open && highlight(layer.range, false));
      layerEls.push(det);
      layersBox.append(det);
    });
    // Pasar por un byte ilumina la capa a la que pertenece (la más interior).
    hexBox.addEventListener("mouseover", (e) => {
      const i = Number(e.target.dataset && e.target.dataset.i);
      if (Number.isNaN(i)) return;
      let found = -1;
      d.layers.forEach((l, k) => {
        if (l.range && i >= l.range[0] && i < l.range[1]) found = k;
      });
      layerEls.forEach((el, k) => el.classList.toggle("active", k === found));
      highlight(found >= 0 ? d.layers[found].range : null, true);
    });
    hexBox.addEventListener("mouseleave", () => {
      layerEls.forEach((el) => el.classList.remove("active"));
      highlight(null);
    });
    const cut = d.captured < d.len ? ` (capturados ${nf.format(d.captured)} de ${nf.format(d.len)} bytes)` : "";
    side.append(
      layersBox,
      h("div", { class: "hex-title" }, `Bytes del paquete n.º ${d.n}${cut} · pasa el ratón para ver a qué capa pertenecen`),
      hexBox,
    );
  }

  /** Volcado hexadecimal clásico; devuelve [spans hex..., spans ascii...]. */
  function renderHex(box, hex) {
    const MAX = 4096;
    const n = Math.min(hex.length / 2, MAX);
    const hexSpans = [];
    const ascSpans = [];
    const frag = document.createDocumentFragment();
    for (let off = 0; off < n; off += 16) {
      const line = h("div", null, h("span", { class: "off" }, off.toString(16).padStart(4, "0")));
      const asc = h("span", { class: "asc" });
      for (let i = off; i < Math.min(off + 16, n); i++) {
        const byte = parseInt(hex.substr(i * 2, 2), 16);
        const hs = h("span", { class: "b", "data-i": i }, hex.substr(i * 2, 2));
        const as = h("span", { class: "b", "data-i": i }, byte >= 0x20 && byte < 0x7f ? String.fromCharCode(byte) : "·");
        hexSpans.push(hs);
        ascSpans.push(as);
        line.append(hs, i % 8 === 7 ? "  " : " ");
        asc.append(as);
      }
      line.append(" ".repeat((16 - Math.min(16, n - off)) * 3), asc);
      frag.append(line);
    }
    if (hex.length / 2 > MAX) frag.append(h("div", { class: "sub" }, `… se muestran los primeros ${nf.format(MAX)} bytes`));
    if (!n) frag.append(h("div", { class: "sub" }, "El contenido de este paquete no se guardó (captura muy grande)."));
    box.append(frag);
    return hexSpans.concat(ascSpans);
  }

  // ------------------------------------------------------------ carga y filtros

  async function loadFlows(filter) {
    const q = filter ? `?filter=${encodeURIComponent(filter)}` : "";
    const data = await api(`/api/flows${q}`);
    state.flows = data.flows;
    if (data.truncated) {
      toast(`Hay ${nf.format(data.total)} conversaciones: se muestran las primeras 10.000. Usa un filtro para acotar.`, "info");
    }
    state.byIdx = new Map(data.flows.map((r) => [r.idx, r]));
  }

  async function loadAll() {
    state.session = await api("/api/session");
    const loaded = state.session.loaded;
    $("#welcome").hidden = loaded;
    if (!loaded) return;
    state.packetCache.clear();
    state.storyFilter = null;
    state.selected = null;
    $("#filter-input").value = "";
    setFilterError(null);
    const [stories] = await Promise.all([api("/api/stories"), loadFlows("")]);
    state.stories = stories;
    renderHeader();
    renderOverview();
    renderStories();
    renderStoryChip();
    renderTable();
    const first = state.stories.length ? state.stories[0].flows[0] : visibleFlows()[0] && visibleFlows()[0].idx;
    if (first != null) select(first);
    else renderDetail();
  }

  function setFilterError(err) {
    const input = $("#filter-input");
    const box = $("#filter-error");
    input.classList.toggle("invalid", !!err);
    box.textContent = err || "";
  }

  async function applyFilter() {
    const expr = $("#filter-input").value.trim();
    try {
      await loadFlows(expr);
      setFilterError(null);
      state.storyFilter = null;
      renderStoryChip();
      renderTable();
      if (!state.byIdx.has(state.selected)) {
        const first = visibleFlows()[0];
        state.selected = null;
        if (first) select(first.idx);
        else renderDetail();
      }
    } catch (err) {
      if (err.status === 400 && err.body) {
        const pos = err.body.pos;
        const where = pos >= expr.length ? "al final" : `en la posición ${pos + 1} («${expr.slice(pos, pos + 12)}»)`;
        setFilterError(`El filtro tiene un error ${where}: ${err.body.error}. Pulsa ? para ver ejemplos.`);
        const input = $("#filter-input");
        input.focus();
        input.setSelectionRange(Math.min(pos, expr.length), expr.length);
      } else toast(err.message);
    }
  }

  async function openFile(file) {
    if (!file) return;
    busy(`Analizando «${file.name}»…`);
    try {
      await api(`/api/open?name=${encodeURIComponent(file.name)}`, { method: "POST", body: file });
      await loadAll();
    } catch (err) {
      toast(`No se pudo abrir «${file.name}»: ${err.message}`);
    } finally {
      busy(null);
      $("#file-input").value = "";
    }
  }

  // ------------------------------------------------------------ preferencias de vista

  function setMode(mode) {
    state.mode = mode;
    pref("mode", mode);
    for (const b of document.querySelectorAll(".segmented button")) b.setAttribute("aria-pressed", String(b.dataset.mode === mode));
    renderTable();
  }

  function syncChips() {
    for (const c of document.querySelectorAll(".chip[data-view]")) c.setAttribute("aria-pressed", String(c.dataset.view === state.view));
  }

  function effectiveTheme() {
    const t = document.documentElement.dataset.theme;
    if (t) return t;
    return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  }

  // ------------------------------------------------------------ ayuda

  const EXAMPLES = [
    ["flow.risk >= 30", "lo que tiene algo de riesgo"],
    ["tcp.port == 443", "conexiones a web segura (HTTPS)"],
    ['dns.qname contains "google"', "consultas DNS que mencionan google"],
    ["ip.src == 192.168.1.30", "todo lo que empezó ese equipo"],
    ["ip.version == 6", "solo tráfico IPv6"],
    ["file.masquerading == true", "descargas con archivos disfrazados"],
    ["tcp.flags.syn && !tcp.flags.psh", "intentos de conexión sin datos (sondas)"],
  ];

  function buildHelp() {
    const ex = clear($("#filter-examples"));
    for (const [expr, what] of EXAMPLES) {
      ex.append(
        h(
          "li",
          null,
          h(
            "button",
            {
              type: "button",
              onclick: () => {
                $("#help").close();
                $("#filter-input").value = expr;
                applyFilter();
              },
            },
            expr,
          ),
          h("span", null, what),
        ),
      );
    }
    const gl = clear($("#glossary"));
    for (const [t, d] of GLOSSARY) {
      if (t.endsWith("s") && DEFS.has(t.slice(0, -1).toLowerCase())) continue; // plurales
      gl.append(h("dt", null, t), h("dd", null, d));
    }
  }

  // ------------------------------------------------------------ arranque

  function bind() {
    $("#open-btn").addEventListener("click", () => $("#file-input").click());
    $("#welcome-open").addEventListener("click", () => $("#file-input").click());
    $("#file-input").addEventListener("change", (e) => openFile(e.target.files[0]));
    $("#filter-form").addEventListener("submit", (e) => {
      e.preventDefault();
      applyFilter();
    });
    $("#filter-clear").addEventListener("click", () => {
      $("#filter-input").value = "";
      applyFilter();
    });
    $("#noise-toggle").addEventListener("change", (e) => {
      state.showNoise = e.target.checked;
      renderTable();
    });
    for (const c of document.querySelectorAll(".chip[data-view]")) {
      c.addEventListener("click", () => {
        state.view = c.dataset.view;
        state.storyFilter = null;
        syncChips();
        renderStoryChip();
        renderTable();
      });
    }
    $("#sort-select").addEventListener("change", (e) => {
      state.sort = e.target.value;
      renderTable();
    });
    for (const b of document.querySelectorAll(".segmented button")) b.addEventListener("click", () => setMode(b.dataset.mode));
    for (const b of document.querySelectorAll(".tabs [role=tab]")) b.addEventListener("click", () => setTab(b.dataset.tab));
    $("#theme-btn").addEventListener("click", () => {
      const next = effectiveTheme() === "dark" ? "light" : "dark";
      document.documentElement.dataset.theme = next;
      pref("theme", next);
    });
    $("#help-btn").addEventListener("click", () => $("#help").showModal());

    document.addEventListener("keydown", (e) => {
      const typing = e.target.closest && e.target.closest("input, select, textarea");
      if (e.key === "F1") {
        e.preventDefault();
        $("#help").showModal();
      } else if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "o") {
        e.preventDefault();
        $("#file-input").click();
      } else if (!typing && e.key === "/") {
        e.preventDefault();
        $("#filter-input").focus();
      } else if (!typing && (e.key === "ArrowDown" || e.key === "ArrowUp")) {
        e.preventDefault();
        moveSelection(e.key === "ArrowDown" ? 1 : -1);
      } else if (e.key === "Escape" && typing) {
        e.target.blur();
      }
    });

    // Arrastrar y soltar una captura en cualquier parte de la ventana.
    let depth = 0;
    window.addEventListener("dragenter", (e) => {
      if (![...(e.dataTransfer?.types || [])].includes("Files")) return;
      depth++;
      $("#drop").hidden = false;
    });
    window.addEventListener("dragleave", () => {
      depth = Math.max(0, depth - 1);
      if (!depth) $("#drop").hidden = true;
    });
    window.addEventListener("dragover", (e) => e.preventDefault());
    window.addEventListener("drop", (e) => {
      e.preventDefault();
      depth = 0;
      $("#drop").hidden = true;
      openFile(e.dataTransfer.files[0]);
    });
  }

  async function start() {
    const theme = pref("theme");
    if (theme === "light" || theme === "dark") document.documentElement.dataset.theme = theme;
    const mode = pref("mode");
    state.mode = mode === "experto" ? "experto" : "simple";
    for (const b of document.querySelectorAll(".segmented button")) b.setAttribute("aria-pressed", String(b.dataset.mode === state.mode));
    bind();
    buildHelp();
    busy("Cargando…");
    try {
      await loadAll();
    } catch (err) {
      toast(`No se pudo conectar con soc-shark: ${err.message}`);
    } finally {
      busy(null);
    }
  }

  start();
})();
