// soc-shark · GUI (ADR-013).
//
// Regla de oro: TODO dato que viene de la captura (dominios, rutas, nombres
// de archivo…) lo controla quien genera el tráfico. Se pinta siempre como
// texto (textContent / nodos de texto), nunca con innerHTML.
"use strict";

(() => {
  const TOKEN = document.querySelector('meta[name="socshark-token"]').content;
  const $ = (sel) => document.querySelector(sel);
  const $$ = (sel) => document.querySelectorAll(sel);

  // ------------------------------------------------------------ DOM seguro

  /** Crea un elemento; los hijos de tipo texto se insertan como texto. */
  function h(tag, attrs, ...kids) {
    const el = document.createElement(tag);
    setAttrs(el, attrs);
    for (const kid of kids.flat(Infinity)) {
      if (kid == null || kid === false) continue;
      el.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
    }
    return el;
  }

  /** Igual que `h`, para SVG. */
  function s(tag, attrs, ...kids) {
    const el = document.createElementNS("http://www.w3.org/2000/svg", tag);
    setAttrs(el, attrs);
    for (const kid of kids.flat(Infinity)) {
      if (kid == null || kid === false) continue;
      el.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
    }
    return el;
  }

  function setAttrs(el, attrs) {
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v == null || v === false) continue;
      if (k === "class") el.setAttribute("class", v);
      // CSSOM, no el atributo: la CSP (sin 'unsafe-inline') bloquea style="…".
      else if (k === "style") Object.assign(el.style, v);
      else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
      else el.setAttribute(k, v === true ? "" : String(v));
    }
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
    flows: [], // [{idx, proto, flow, explain}]
    byIdx: new Map(),
    stories: [],
    mode: "simple",
    show: "todo", // todo | importante
    showNoise: false,
    filter: "", // filtro aplicado (no lo que se está escribiendo)
    combine: false,
    history: [],
    sort: { key: "time", dir: 1 },
    rowLimit: 2000,
    visibleCount: 0,
    detailSig: null,
    storyFilter: null, // {title, idx: Set}
    selectedKey: null, // flow_id + inicio: estable entre fotos en vivo
    tab: "explain",
    cache: new Map(), // `${gen}:${tipo}:${idx}` → respuesta
    packetSel: null,
    view: "flows",
    ifaces: [],
    hosts: new Map(), // ip → lo que se sabe del equipo (quién es quién)
    polling: null,
    refreshing: false,
    lastStats: 0,
    measure: "packets",
    pk: { key: null, total: 0, pages: new Map(), stale: new Map(), pending: new Set(), sel: null, selPos: -1, follow: true },
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

  const gen = () => (state.session && state.session.generation) || 0;
  const isLive = () => !!(state.session && state.session.live);
  const liveRunning = () => !!(state.session && state.session.live && state.session.live.running);

  // ------------------------------------------------------------ formato

  const LEVEL = {
    ok: { icon: "✓", label: "Normal" },
    raro: { icon: "!", label: "Raro" },
    peligro: { icon: "✕", label: "Peligro" },
  };
  const RANK = { ok: 0, raro: 1, peligro: 2 };
  const STATE_ES = { Active: "activa", Idle: "sin cerrar", Closed: "cerrada" };
  const nf = new Intl.NumberFormat("es-ES");
  const compact = new Intl.NumberFormat("es-ES", { notation: "compact", maximumFractionDigits: 1 });

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
  function fmtClock(us) {
    const d = new Date(us / 1000);
    return `${fmtTime(us)},${String(d.getMilliseconds()).padStart(3, "0")}`;
  }
  function fmtDuration(us) {
    const sec = us / 1e6;
    if (sec < 1) return `${(sec * 1000).toLocaleString("es-ES", { maximumFractionDigits: 1 })} ms`;
    if (sec < 120) return `${sec.toLocaleString("es-ES", { maximumFractionDigits: 1 })} s`;
    const m = Math.floor(sec / 60);
    if (m < 120) return `${m} min ${Math.round(sec - m * 60)} s`;
    return `${Math.floor(m / 60)} h ${m % 60} min`;
  }
  function fmtElapsed(us) {
    const t = Math.max(0, Math.floor(us / 1e6));
    const hh = Math.floor(t / 3600);
    const mm = String(Math.floor((t % 3600) / 60)).padStart(2, "0");
    const ss = String(t % 60).padStart(2, "0");
    return hh ? `${hh}:${mm}:${ss}` : `${mm}:${ss}`;
  }
  const fmtRel = (us) => (us / 1e6).toLocaleString("es-ES", { minimumFractionDigits: 6, maximumFractionDigits: 6 });
  const fmtRelShort = (us) =>
    "+" + (us / 1e6).toLocaleString("es-ES", { minimumFractionDigits: 3, maximumFractionDigits: 3 }) + " s";
  const endpoint = (ip, port) => (ip.includes(":") ? `[${ip}]:${port}` : `${ip}:${port}`);
  const hasPorts = (f) => f.transport === "Tcp" || f.transport === "Udp";
  const transportName = (f) => (typeof f.transport === "string" ? f.transport.toUpperCase() : "OTRO");
  const TRANSPORTS = ["TCP", "UDP", "ICMP", "OTRO"];
  const ep = (f, side) =>
    side === "src"
      ? hasPorts(f) ? endpoint(f.src_ip, f.src_port) : f.src_ip
      : hasPorts(f) ? endpoint(f.dst_ip, f.dst_port) : f.dst_ip;
  const plural = (n, one, many) => (n === 1 ? `1 ${one}` : `${nf.format(n)} ${many}`);

  // ------------------------------------------------------------ quién es quién

  const hostOf = (ip) => state.hosts.get(ip);
  /** Dirección de la red local (las únicas a las que se pone nombre). */
  const isLanIp = (ip) =>
    /^(10\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.)/.test(ip) || /^(f[cd]|fe[89ab])[0-9a-f]*:/i.test(ip);

  /** Lo que se sabe de un equipo, en frases cortas. */
  function hostFacts(hst) {
    if (!hst) return [];
    const out = [];
    if (hst.nickname && hst.name) out.push(`se presenta como «${hst.name}»`);
    if (hst.vendor) out.push(hst.vendor_hint ? `marca ${hst.vendor} (suele ser ${hst.vendor_hint})` : `marca ${hst.vendor}`);
    if (hst.os) out.push(`con ${hst.os}`);
    if (hst.random_mac) out.push("MAC aleatoria: móvil o portátil con privacidad activada");
    if (hst.name && hst.name_source && !hst.nickname) out.push(`nombre anunciado por ${hst.name_source}`);
    return out;
  }

  function renameButton(ip) {
    if (!isLanIp(ip)) return null;
    const hst = hostOf(ip);
    return h(
      "button",
      {
        class: "btn link",
        type: "button",
        title: "Ponle un nombre que reconozcas («Portátil de Ana»)",
        onclick: (e) => {
          e.stopPropagation();
          openNickDialog(ip);
        },
      },
      hst && hst.nickname ? "Cambiar nombre" : "Ponerle nombre",
    );
  }

  /** «Quién empezó» / «Con quién»: nombre, dirección y lo que se sabe. */
  function whoFact(ip, endpointText, extra) {
    const hst = hostOf(ip);
    const facts = hostFacts(hst);
    return [
      hst && hst.short ? h("b", { class: "host-name" }, hst.short, " ") : null,
      h("span", { class: "mono" }, endpointText),
      extra ? ` · ${extra}` : "",
      " ",
      renameButton(ip),
      facts.length ? h("div", { class: "sub" }, facts.join(" · ")) : null,
    ];
  }

  async function loadHosts() {
    try {
      const list = await api("/api/hosts");
      state.hosts = new Map(list.map((x) => [x.ip, x]));
    } catch {
      state.hosts = new Map();
    }
  }

  let nickTarget = null;
  function openNickDialog(ip) {
    const hst = hostOf(ip);
    nickTarget = { key: hst ? hst.key : `ip:${ip}`, ip };
    const who = [hst && hst.short, ip, hst && hst.mac ? `MAC ${hst.mac}` : null].filter(Boolean).join(" · ");
    $("#nick-who").textContent = who;
    $("#nick-input").value = (hst && hst.nickname) || "";
    $("#nick-remove").hidden = !(hst && hst.nickname);
    $("#nick-error").hidden = true;
    $("#nick-dlg").showModal();
    $("#nick-input").focus();
  }

  async function saveNick(name) {
    if (!nickTarget) return;
    const err = $("#nick-error");
    try {
      const ses = await api(`/api/hosts/nick?key=${encodeURIComponent(nickTarget.key)}&name=${encodeURIComponent(name)}`, { method: "POST" });
      $("#nick-dlg").close();
      await refresh(ses);
      renderDetail();
      toast(name ? `Ahora se llama «${name.trim()}».` : "Nombre quitado.", "info");
    } catch (e) {
      err.hidden = false;
      err.textContent = e.message;
    }
  }

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
    ["ICMP", "Mensajes de control de la red, como el «ping» o los avisos de «no se puede llegar»."],
    ["TLS", "El cifrado que protege las conexiones (el candado del navegador)."],
    ["HTTPS", "Web cifrada: se sabe con qué web hablas, pero no qué ves ni envías."],
    ["HTTP", "Web sin cifrar: cualquiera en la red puede leer lo que se envía."],
    ["QUIC", "La versión moderna de la web segura, que va sobre UDP (HTTP/3)."],
    ["SSH", "Acceso remoto seguro (cifrado) para administrar equipos a distancia."],
    ["Telnet", "Acceso remoto antiguo y sin cifrar: usuario y contraseña viajan a la vista."],
    ["SMB", "El protocolo de las carpetas compartidas de Windows."],
    ["RDP", "Escritorio remoto de Windows."],
    ["NTP", "El protocolo con el que los equipos ponen su reloj en hora."],
    ["DHCP", "El servicio que reparte direcciones IP a los equipos que se conectan a la red."],
    ["mDNS", "Anuncios automáticos en la red local (impresoras, móviles, televisores…)."],
    ["SSDP", "Anuncios de dispositivos de casa (televisores, routers, altavoces) para encontrarse entre sí."],
    ["BPF", "Lenguaje de filtros de captura (el de tcpdump): decide qué paquetes se guardan."],
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
    ["loopback", "La red interna del propio equipo: programas que hablan entre sí sin salir a la red."],
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
  const escapeRe = (x) => x.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
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
  /** Muestra el tooltip junto a un rectángulo (el de un término o una barra). */
  function showTipAt(r, ...kids) {
    clear(tooltip).append(...kids);
    tooltip.hidden = false;
    const tw = tooltip.offsetWidth;
    const th = tooltip.offsetHeight;
    const x = Math.min(Math.max(8, r.left), window.innerWidth - tw - 8);
    let y = r.bottom + 6;
    if (y + th > window.innerHeight - 8) y = r.top - th - 6;
    tooltip.style.left = `${x}px`;
    tooltip.style.top = `${Math.max(8, y)}px`;
  }
  function showTip(target) {
    const def = DEFS.get(target.dataset.term);
    if (def) showTipAt(target.getBoundingClientRect(), h("b", null, def[0]), def[1]);
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
    setTimeout(() => t.remove(), kind === "error" ? 8000 : 4000);
    t.addEventListener("click", () => t.remove());
  }

  function busy(text) {
    $("#busy").hidden = !text;
    if (text) $("#busy-text").textContent = text;
  }

  // ------------------------------------------------------------ expresiones de filtro

  const ipLit = (ip) => (ip.includes(":") ? `"${ip}"` : ip);
  const quoteStr = (v) => `"${String(v).replace(/["\\]/g, "\\$&")}"`;
  const exprHost = (ip) => `ip.addr == ${ipLit(ip)}`;
  const exprNotHost = (ip) => `!(ip.addr == ${ipLit(ip)})`;
  function exprConv(f) {
    const base = `ip.src == ${ipLit(f.src_ip)} && ip.dst == ${ipLit(f.dst_ip)}`;
    return hasPorts(f) ? `${base} && sport == ${f.src_port} && dport == ${f.dst_port}` : base;
  }
  function exprProto(name) {
    if (TRANSPORTS.includes(name)) return `transport == "${name}" && proto == "?"`;
    return `proto == ${quoteStr(name)}`;
  }
  const exprService = (port, transport) => `dport == ${port} && transport == "${transport}"`;

  // ------------------------------------------------------------ resumen

  function renderOverview() {
    const ov = clear($("#overview"));
    const ses = state.session;
    if (!ses || !ses.loaded) return;
    const stat = (cls, n, label) =>
      h("div", { class: `stat ${cls}` }, h("span", { class: "n" }, nf.format(n)), h("span", { class: "l" }, label));
    ov.append(
      stat("peligro", ses.levels.peligro, ses.levels.peligro === 1 ? "peligro" : "peligros"),
      stat("raro", ses.levels.raro, ses.levels.raro === 1 ? "cosa rara" : "cosas raras"),
      stat("ok", ses.levels.ok, ses.levels.ok === 1 ? "normal" : "normales"),
    );
    const span = ses.first_seen != null && ses.last_seen != null ? ses.last_seen - ses.first_seen : 0;
    const dur = span > 0 ? ` · ${fmtDuration(span)} de tráfico` : "";
    ov.append(
      h(
        "div",
        { class: "meta" },
        `${plural(ses.flows, "conversación", "conversaciones")} (${nf.format(ses.noise)} de fondo)${dur}`,
        ses.packets_truncated ? " · captura muy grande: algunos paquetes no muestran su contenido" : "",
      ),
    );
  }

  function renderStories() {
    const list = clear($("#stories"));
    if (!state.stories.length) {
      const waiting = liveRunning() && !state.session.flows;
      list.append(
        h(
          "li",
          { class: "all-good" },
          h("b", null, waiting ? "Escuchando…" : "✓ No hemos visto nada preocupante"),
          waiting
            ? "En cuanto pase algo por la red aparecerá aquí, explicado."
            : "Puedes revisar igualmente las conversaciones si buscas algo concreto.",
        ),
      );
      return;
    }
    for (const st of state.stories) {
      const n = st.flows.length;
      list.append(
        h(
          "li",
          { class: `story ${st.level}` },
          h("h3", null, dot(st.level), h("span", null, st.title)),
          h("p", null, rich(st.story)),
          h("p", { class: "todo" }, rich(st.action)),
          h(
            "div",
            { class: "actions" },
            h("button", { class: "btn small", type: "button", onclick: () => showStory(st) }, n === 1 ? "Ver la conversación" : `Ver las ${n} conversaciones`),
            mitreLink(st.mitre),
          ),
        ),
      );
    }
  }

  function showStory(story) {
    state.storyFilter = { title: story.title, idx: new Set(story.flows) };
    // Una historia puede incluir tráfico de fondo o normal: se muestra todo.
    state.show = "todo";
    syncChips();
    switchView("flows");
    renderStoryChip();
    renderTable();
    const first = visibleFlows()[0];
    if (first) select(first.idx);
  }

  function renderStoryChip() {
    const chip = clear($("#story-chip"));
    chip.hidden = !state.storyFilter || state.view !== "flows";
    if (chip.hidden) return;
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
            renderStatus();
          },
        },
        "✕",
      ),
    );
  }

  // ------------------------------------------------------------ tabla de conversaciones

  const flowBytes = (r) => r.flow.bytes + r.flow.bytes_rev;
  const flowPackets = (r) => r.flow.packets + r.flow.packets_rev;
  const levelKey = (r) => RANK[r.explain.level] * 1000 + r.flow.risk_score;

  const COLUMNS = {
    simple: [
      { key: "level", label: "", title: "Gravedad", sort: levelKey, desc: true },
      { key: "what", label: "Qué pasó", sort: (r) => r.explain.headline },
      { key: "time", label: "Hora", sort: (r) => r.flow.first_seen_micros },
      { key: "bytes", label: "Datos", num: true, sort: flowBytes, desc: true },
    ],
    experto: [
      { key: "level", label: "", title: "Gravedad", sort: levelKey, desc: true },
      { key: "time", label: "Inicio", sort: (r) => r.flow.first_seen_micros },
      { key: "proto", label: "Protocolo", sort: (r) => r.proto },
      { key: "src", label: "Origen", sort: (r) => r.flow.src_ip },
      { key: "dst", label: "Destino", sort: (r) => r.flow.dst_ip },
      { key: "packets", label: "Paquetes", num: true, sort: flowPackets, desc: true },
      { key: "bytes", label: "Bytes", num: true, sort: flowBytes, desc: true },
      { key: "dur", label: "Duración", num: true, sort: (r) => r.flow.duration_micros, desc: true },
      { key: "risk", label: "Riesgo", num: true, sort: (r) => r.flow.risk_score, desc: true },
      { key: "alerts", label: "Alertas", sort: (r) => r.flow.alerts.map((a) => a.id).join(",") },
    ],
  };

  function visibleFlows() {
    let list = state.flows;
    if (state.storyFilter) list = list.filter((r) => state.storyFilter.idx.has(r.idx));
    else {
      if (!state.showNoise) list = list.filter((r) => !r.flow.is_background_noise);
      if (state.show === "importante") list = list.filter((r) => r.explain.level !== "ok");
    }
    const col = [...COLUMNS.simple, ...COLUMNS.experto].find((c) => c.key === state.sort.key) || COLUMNS.simple[2];
    const dir = state.sort.dir;
    return [...list].sort((a, b) => {
      const x = col.sort(a);
      const y = col.sort(b);
      const c = typeof x === "string" ? x.localeCompare(y, "es") : x - y;
      return c * dir || a.idx - b.idx;
    });
  }

  function flowCells(r) {
    const f = r.flow;
    const e = r.explain;
    if (state.mode !== "experto") {
      return [
        h("td", null, dot(e.level)),
        h(
          "td",
          null,
          h("div", { class: "headline" }, e.headline),
          h("div", { class: "sub mono" }, `${r.proto} · ${ep(f, "src")} → ${ep(f, "dst")}`),
        ),
        h("td", { class: "time" }, fmtTime(f.first_seen_micros)),
        h("td", { class: "num" }, fmtBytes(f.bytes + f.bytes_rev)),
      ];
    }
    return [
      h("td", null, dot(e.level)),
      h("td", { class: "time" }, fmtTime(f.first_seen_micros)),
      h("td", { class: "mono" }, r.proto),
      h("td", { class: "mono" }, ep(f, "src"), r.src_name ? h("div", { class: "sub", title: r.src_name }, r.src_name) : null),
      h(
        "td",
        { class: "mono" },
        ep(f, "dst"),
        r.dst_name || f.resolved_domain
          ? h("div", { class: "sub", title: r.dst_name || f.resolved_domain }, r.dst_name || f.resolved_domain)
          : null,
      ),
      h("td", { class: "num" }, nf.format(f.packets + f.packets_rev)),
      h("td", { class: "num" }, fmtBytes(f.bytes + f.bytes_rev)),
      h("td", { class: "num" }, fmtDuration(f.duration_micros)),
      h("td", { class: `num risk ${e.level}` }, f.risk_score),
      h("td", { class: "mono" }, f.alerts.map((a) => a.id).join(", ") || "—"),
    ];
  }

  function renderHead() {
    const cols = COLUMNS[state.mode === "experto" ? "experto" : "simple"];
    const head = clear($("#flows-head"));
    head.append(
      h(
        "tr",
        null,
        cols.map((c) => {
          const on = state.sort.key === c.key;
          return h(
            "th",
            {
              scope: "col",
              class: c.num ? "num" : null,
              "aria-sort": on ? (state.sort.dir > 0 ? "ascending" : "descending") : null,
            },
            h(
              "button",
              {
                type: "button",
                title: `Ordenar por ${(c.title || c.label).toLowerCase()}`,
                "aria-label": c.label ? null : c.title,
                onclick: () => {
                  state.sort = on ? { key: c.key, dir: -state.sort.dir } : { key: c.key, dir: c.desc ? -1 : 1 };
                  renderTable();
                },
              },
              c.label,
            ),
          );
        }),
      ),
    );
    return cols.length;
  }

  function renderTable() {
    const ncols = renderHead();
    const body = clear($("#flows-body"));
    const rows = visibleFlows();
    const frag = document.createDocumentFragment();
    for (const r of rows.slice(0, state.rowLimit)) {
      const f = r.flow;
      const cls = [f.is_background_noise ? "noise" : null, r.explain.level !== "ok" ? r.explain.level : null].filter(Boolean).join(" ");
      frag.append(
        h(
          "tr",
          {
            class: cls || null,
            "aria-selected": String(flowKey(r) === state.selectedKey),
            "data-idx": r.idx,
            tabindex: "-1",
            onclick: () => select(r.idx),
            oncontextmenu: (e) => {
              e.preventDefault();
              select(r.idx);
              openMenu(e.clientX, e.clientY, flowMenu(r));
            },
          },
          flowCells(r),
        ),
      );
    }
    if (rows.length > state.rowLimit) {
      frag.append(
        h(
          "tr",
          { class: "more" },
          h(
            "td",
            { colspan: ncols },
            `Se muestran ${nf.format(state.rowLimit)} de ${nf.format(rows.length)}. `,
            h(
              "button",
              {
                class: "btn small",
                type: "button",
                onclick: () => {
                  state.rowLimit += 2000;
                  renderTable();
                },
              },
              "Mostrar más",
            ),
            " o usa un filtro para acotar.",
          ),
        ),
      );
    }
    body.append(frag);

    state.visibleCount = rows.length;
    const total = state.flows.length;
    $("#flows-count").textContent = rows.length === total ? `(${nf.format(total)})` : `(${nf.format(rows.length)} de ${nf.format(total)})`;
    const empty = $("#flows-empty");
    empty.hidden = rows.length > 0;
    if (!rows.length) {
      empty.textContent = liveRunning() && !state.session.flows
        ? "Escuchando… las conversaciones aparecerán aquí en cuanto haya tráfico."
        : state.show === "importante" && !state.storyFilter
          ? "Nada importante con estos filtros. ¡Buena señal!"
          : "Ninguna conversación coincide con el filtro.";
    }
    renderStatus();
  }

  const flowKey = (r) => `${r.flow.flow_id}@${r.flow.first_seen_micros}`;
  /** Cambia si la conversación recibió algo nuevo (en vivo). */
  const detailSig = (r) => `${state.tab}|${flowPackets(r)}|${r.flow.risk_score}|${r.flow.alerts.length}|${r.flow.state}`;
  const selectedRow = () => state.flows.find((r) => flowKey(r) === state.selectedKey) || null;

  function select(idx, { focus = false } = {}) {
    const r = state.byIdx.get(idx);
    const key = r ? flowKey(r) : null;
    if (key !== state.selectedKey) state.packetSel = null;
    state.selectedKey = key;
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
    const rows = visibleFlows().slice(0, state.rowLimit);
    if (!rows.length) return;
    const pos = rows.findIndex((r) => flowKey(r) === state.selectedKey);
    const next = rows[Math.min(rows.length - 1, Math.max(0, pos < 0 ? 0 : pos + delta))];
    select(next.idx, { focus: true });
  }

  // ------------------------------------------------------------ detalle de una conversación

  function setTab(tab) {
    state.tab = tab;
    for (const b of $$(".tabs [role=tab]")) b.setAttribute("aria-selected", String(b.dataset.tab === tab));
    renderDetail();
  }

  /** `soft`: refresco en vivo; conserva el desplazamiento y el paquete elegido. */
  function renderDetail({ soft = false } = {}) {
    const box = $("#detail");
    const keep = soft ? { top: box.scrollTop, inner: box.querySelector(".pkt-list, .stream")?.scrollTop } : null;
    clear(box);
    const r = selectedRow();
    const pk = $("#tab-packets");
    if (!r) {
      pk.textContent = "Paquetes";
      box.append(h("p", { class: "placeholder" }, state.flows.length ? "Elige una conversación de la lista para ver qué pasó." : ""));
      return;
    }
    pk.textContent = `Paquetes (${nf.format(flowPackets(r))})`;
    state.detailSig = detailSig(r);
    const restore = () => {
      if (!keep) return;
      box.scrollTop = keep.top;
      const inner = box.querySelector(".pkt-list, .stream");
      if (inner && keep.inner != null) inner.scrollTop = keep.inner;
    };
    if (state.tab === "explain") renderExplain(box, r);
    else if (state.tab === "packets") return renderFlowPackets(box, r).then(restore);
    else if (state.tab === "stream") return renderStream(box, r).then(restore);
    else box.append(h("pre", { class: "json" }, JSON.stringify(r.flow, null, 2)));
    restore();
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
    fact("Quién empezó", ...whoFact(f.src_ip, ep(f, "src")));
    if (f.process_name) {
      fact("Programa", h("b", null, f.process_name), f.pid != null ? h("span", { class: "sub" }, ` · proceso ${f.pid}`) : null);
    }
    fact("Con quién", ...whoFact(f.dst_ip, ep(f, "dst"), hostOf(f.dst_ip) && hostOf(f.dst_ip).short ? null : f.resolved_domain));
    fact("Protocolo", rich(TRANSPORTS.includes(r.proto) ? r.proto : `${r.proto} sobre ${transportName(f)}`));
    fact("Cuándo", `${fmtDateTime(f.first_seen_micros)} · duró ${fmtDuration(f.duration_micros)}`);
    fact(
      "Volumen",
      `ida: ${plural(f.packets, "paquete", "paquetes")} (${fmtBytes(f.bytes)}) · vuelta: ${plural(f.packets_rev, "paquete", "paquetes")} (${fmtBytes(f.bytes_rev)})`,
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
    box.append(
      h(
        "div",
        { class: "detail-actions" },
        h("button", { class: "btn small", type: "button", onclick: () => setTab("stream") }, "Ver lo que se dijeron"),
        h("button", { class: "btn small", type: "button", onclick: () => applyAsFilter(exprConv(f)) }, "Filtrar esta conversación"),
        h("button", { class: "btn small", type: "button", onclick: () => applyAsFilter(exprHost(f.src_ip)) }, `Todo de ${f.src_ip}`),
      ),
    );
  }

  /** Respuesta cacheada por foto (en vivo cada foto trae paquetes nuevos). */
  async function cached(kind, idx, path) {
    const key = `${gen()}:${kind}:${idx}`;
    if (!state.cache.has(key)) {
      if (state.cache.size > 64) state.cache.clear();
      state.cache.set(key, await api(path));
    }
    return state.cache.get(key);
  }

  async function renderFlowPackets(box, r) {
    const key = state.selectedKey;
    let data;
    try {
      data = await cached("packets", r.idx, `/api/flows/${r.idx}/packets`);
    } catch (err) {
      clear(box).append(h("p", { class: "placeholder" }, `No se pudieron cargar los paquetes: ${err.message}`));
      return;
    }
    if (state.selectedKey !== key || state.tab !== "packets") return; // el usuario ya cambió
    clear(box);
    if (!data.packets.length) {
      box.append(h("p", { class: "placeholder" }, "Esta conversación no tiene paquetes que mostrar."));
      return;
    }
    const side = h("div", { class: "pkt-side" });
    const tbody = h("tbody");
    const list = h(
      "div",
      { class: "pkt-list" },
      h(
        "table",
        { class: "grid" },
        h("thead", null, h("tr", null, ["N.º", "Tiempo", "", "Tamaño", "Qué hace"].map((c) => h("th", null, h("span", null, c))))),
        tbody,
      ),
    );
    for (const p of data.packets) {
      tbody.append(
        h(
          "tr",
          { "data-n": p.n, "aria-selected": "false", onclick: () => pickFlowPacket(p.n, tbody, side) },
          h("td", { class: "num" }, p.n),
          h("td", { class: "num" }, fmtRelShort(p.rel_micros)),
          h("td", { class: `dir ${p.outbound ? "out" : "in"}`, title: p.outbound ? "de quien empezó hacia el otro lado" : "respuesta" }, p.outbound ? "→" : "←"),
          h("td", { class: "num" }, fmtBytes(p.len)),
          h("td", null, p.summary),
        ),
      );
    }
    if (data.more) tbody.append(h("tr", { class: "more" }, h("td", { colspan: "5" }, "Solo se muestran los primeros 5.000 paquetes de esta conversación.")));
    box.append(h("div", { class: "packets" }, list, side));
    const keepN = data.packets.some((p) => p.n === state.packetSel) ? state.packetSel : data.packets[0].n;
    await pickFlowPacket(keepN, tbody, side);
  }

  async function pickFlowPacket(n, tbody, side) {
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
    const view = buildPacketDetail(d);
    clear(side).append(view.layers, view.hexTitle, view.hex);
  }

  /** Capas (explicadas) + volcado hexadecimal enlazados entre sí. */
  function buildPacketDetail(d) {
    const layersBox = h("div", { class: "layers" });
    const hexBox = h("div", { class: "hex", "aria-label": "Bytes del paquete" });
    const spans = renderHex(hexBox, d.hex);
    const half = spans.length / 2;
    const layerEls = [];
    const highlight = (range, hot) => {
      for (const sp of spans) sp.classList.remove("in-layer", "hot");
      if (!range) return;
      for (let i = range[0]; i < Math.min(range[1], half); i++) {
        spans[i].classList.add(hot ? "hot" : "in-layer");
        spans[i + half].classList.add(hot ? "hot" : "in-layer");
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
    return {
      layers: layersBox,
      hex: hexBox,
      hexTitle: h("div", { class: "hex-title" }, `Bytes del paquete n.º ${d.n}${cut} · pasa el ratón para ver a qué capa pertenecen`),
    };
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

  // ------------------------------------------------------------ contenido (seguir la conversación)

  function hexToBytes(hex) {
    const out = new Uint8Array(hex.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
    return out;
  }

  /** Bytes como texto legible: UTF-8 si lo es, si no carácter a carácter. */
  function bytesToText(bytes) {
    let text;
    try {
      text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    } catch {
      text = Array.from(bytes, (b) => (b >= 0x20 && b < 0x7f) || b === 9 || b === 10 || b === 13 ? String.fromCharCode(b) : "·").join("");
    }
    return text.replace(/\r\n/g, "\n").replace(/[\u0000-\u0008\u000b-\u001f\u007f]/g, "·");
  }

  function bytesToHexdump(bytes) {
    const lines = [];
    for (let off = 0; off < bytes.length; off += 16) {
      const row = bytes.subarray(off, off + 16);
      const hx = Array.from(row, (b) => b.toString(16).padStart(2, "0")).join(" ");
      const asc = Array.from(row, (b) => (b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : "·")).join("");
      lines.push(`${off.toString(16).padStart(6, "0")}  ${hx.padEnd(47)}  ${asc}`);
    }
    return lines.join("\n");
  }

  async function renderStream(box, r) {
    const key = state.selectedKey;
    let v;
    try {
      v = await cached("stream", r.idx, `/api/flows/${r.idx}/stream`);
    } catch (err) {
      clear(box).append(h("p", { class: "placeholder" }, `No se pudo reconstruir la conversación: ${err.message}`));
      return;
    }
    if (state.selectedKey !== key || state.tab !== "stream") return;
    clear(box);
    const f = r.flow;
    const mode = pref("stream") === "hex" ? "hex" : "text";
    const chunks = v.chunks.map((c) => ({ ...c, bytes: hexToBytes(c.hex) }));
    const asText = (c) => (mode === "hex" ? bytesToHexdump(c.bytes) : bytesToText(c.bytes));
    const seg = h(
      "div",
      { class: "segmented small", role: "group", "aria-label": "Formato" },
      [
        ["text", "Texto"],
        ["hex", "Hex"],
      ].map(([m, label]) =>
        h(
          "button",
          {
            type: "button",
            "aria-pressed": String(mode === m),
            onclick: () => {
              pref("stream", m);
              renderDetail();
            },
          },
          label,
        ),
      ),
    );
    const copy = h(
      "button",
      {
        class: "btn small",
        type: "button",
        disabled: chunks.length ? null : true,
        onclick: async () => {
          try {
            await navigator.clipboard.writeText(chunks.map(asText).join("\n"));
            toast("Contenido copiado al portapapeles.", "info");
          } catch {
            toast("No se pudo copiar al portapapeles.");
          }
        },
      },
      "Copiar",
    );
    box.append(
      h(
        "div",
        { class: "stream-head" },
        h("span", { class: "who out" }, h("i"), `${ep(f, "src")} (empezó) · ${fmtBytes(v.client_bytes)}`),
        h("span", { class: "who in" }, h("i"), `${ep(f, "dst")} (respondió) · ${fmtBytes(v.server_bytes)}`),
        h("span", { class: "spacer" }),
        seg,
        copy,
      ),
    );
    const notes = [];
    const encrypted = r.proto === "TLS" || r.proto === "SSH" || (f.transport === "Udp" && f.dst_port === 443);
    if (!chunks.length) notes.push("Esta conversación no lleva datos: solo mensajes de control (abrir, confirmar, cerrar).");
    else if (encrypted) notes.push("Va cifrada: lo que ves son datos sin sentido. Es buena señal: nadie en la red puede leerla.");
    else notes.push("Esto es lo que se dijeron, tal cual viajó por la red. Si ves contraseñas o datos personales, cualquiera en la red podía verlos.");
    if (v.gaps) notes.push("Faltan trozos: la captura no vio algunos paquetes.");
    if (v.truncated) notes.push("Solo se muestra el primer mega.");
    box.append(h("p", { class: "stream-note" }, rich(notes.join(" "))));
    if (!chunks.length) return;
    const pre = h("div", { class: "stream", tabindex: "0", "aria-label": "Contenido de la conversación" });
    for (const c of chunks) {
      pre.append(
        h(
          "pre",
          { class: `chunk ${c.outbound ? "out" : "in"}${mode === "hex" ? " hexmode" : ""}`, title: `paquete n.º ${c.n} · ${c.outbound ? "enviado por quien empezó" : "respuesta"}` },
          asText(c),
        ),
      );
    }
    box.append(pre);
  }

  // ------------------------------------------------------------ lista global de paquetes (virtual)

  const ROW_H = 26;
  const PAGE = 200;

  function viewQuery() {
    const q = [];
    if (state.filter) q.push(`filter=${encodeURIComponent(state.filter)}`);
    if (!state.showNoise) q.push("noise=0");
    if (state.show === "importante") q.push("important=1");
    return q.join("&");
  }

  function pkReset() {
    const pk = state.pk;
    pk.key = `${gen()}|${viewQuery()}`;
    pk.pages.clear();
    pk.stale.clear();
    pk.pending.clear();
    loadPage(0);
  }

  async function loadPage(p) {
    const pk = state.pk;
    const key = pk.key;
    const tag = `${key}#${p}`;
    if (pk.pending.has(tag)) return;
    pk.pending.add(tag);
    try {
      const q = viewQuery();
      const data = await api(`/api/packets?offset=${p * PAGE}&limit=${PAGE}${q ? "&" + q : ""}`);
      if (pk.key !== key) return;
      pk.pages.set(p, data.packets);
      const changed = pk.total !== data.total;
      pk.total = data.total;
      if (changed && pk.follow && liveRunning()) scrollToEnd();
      pkRender();
    } catch (err) {
      if (pk.key === key) toast(`No se pudieron cargar los paquetes: ${err.message}`);
    } finally {
      pk.pending.delete(tag);
    }
  }

  let programmaticScroll = false;
  function scrollToEnd() {
    const box = $("#vlist");
    programmaticScroll = true;
    $("#vlist-sizer").style.height = `${state.pk.total * ROW_H}px`;
    box.scrollTop = box.scrollHeight;
  }

  function pkRender() {
    const pk = state.pk;
    const box = $("#vlist");
    const sizer = $("#vlist-sizer");
    sizer.style.height = `${pk.total * ROW_H}px`;
    $("#pk-count").textContent = `(${nf.format(pk.total)})`;
    const empty = $("#pk-empty");
    empty.hidden = pk.total > 0;
    box.hidden = pk.total === 0;
    if (!pk.total) {
      empty.textContent = liveRunning() ? "Escuchando… los paquetes aparecerán aquí." : "Ningún paquete coincide con el filtro.";
    }
    const first = Math.max(0, Math.floor(box.scrollTop / ROW_H) - 8);
    const last = Math.min(pk.total, Math.ceil((box.scrollTop + box.clientHeight) / ROW_H) + 8);
    for (let p = Math.floor(first / PAGE); p <= Math.floor(Math.max(first, last - 1) / PAGE); p++) {
      if (!pk.pages.has(p) && p * PAGE < pk.total) loadPage(p);
    }
    const frag = document.createDocumentFragment();
    for (let i = first; i < last; i++) {
      const page = Math.floor(i / PAGE);
      const row = (pk.pages.get(page) || pk.stale.get(page))?.[i % PAGE];
      const top = { top: `${i * ROW_H}px` };
      if (!row) {
        frag.append(h("div", { class: "vrow grid-row loading", style: top }, h("span", null, "…")));
        continue;
      }
      const cls = ["vrow", "grid-row", row.level && row.level !== "ok" ? row.level : null].filter(Boolean).join(" ");
      frag.append(
        h(
          "div",
          {
            class: cls,
            style: top,
            role: "option",
            "aria-selected": String(row.n === pk.sel),
            "data-pos": i,
            onclick: () => pkSelect(i, row),
            ondblclick: () => goToFlow(row.flow),
            oncontextmenu: (e) => {
              e.preventDefault();
              pkSelect(i, row);
              openMenu(e.clientX, e.clientY, packetMenu(row));
            },
          },
          h("span", { class: "num" }, row.n),
          h("span", { class: "num" }, fmtRel(row.rel_micros)),
          h("span", { title: row.src }, row.src || "—"),
          h("span", { title: row.dst }, row.dst || "—"),
          h("span", { class: "proto-tag" }, row.protocol || "—"),
          h("span", { class: "num" }, nf.format(row.len)),
          h("span", { title: row.summary }, row.summary),
        ),
      );
    }
    clear(sizer).append(frag);
    if (pk.shown !== pk.total) {
      pk.shown = pk.total;
      renderStatus();
    }
  }

  function pkSelect(pos, row) {
    const pk = state.pk;
    pk.sel = row.n;
    pk.selPos = pos;
    for (const el of $("#vlist-sizer").children) el.setAttribute("aria-selected", String(Number(el.dataset.pos) === pos));
    showGlobalPacket(row);
  }

  async function showGlobalPacket(row) {
    const box = $("#pk-detail");
    let d;
    try {
      d = await api(`/api/packets/${row.n}`);
    } catch (err) {
      clear(box).append(h("p", { class: "placeholder" }, err.message));
      return;
    }
    if (state.pk.sel !== row.n) return;
    const view = buildPacketDetail(d);
    const flow = row.flow != null ? state.byIdx.get(row.flow) : null;
    const title = h(
      "div",
      { class: "pk-title" },
      row.level ? dot(row.level) : null,
      h("b", null, `Paquete n.º ${d.n}`),
      h("span", { class: "sub" }, `${fmtClock(d.ts_micros)} · ${nf.format(d.len)} bytes`),
      flow ? h("button", { class: "btn small", type: "button", onclick: () => goToFlow(row.flow) }, "Ir a su conversación") : null,
    );
    clear(box).append(
      h("div", { class: "layers" }, title, flow ? h("p", { class: "sub" }, flow.explain.headline) : null, view.layers),
      h("div", { class: "hex-col" }, view.hexTitle, view.hex),
    );
  }

  function pkMove(delta) {
    const pk = state.pk;
    if (!pk.total) return;
    const pos = Math.min(pk.total - 1, Math.max(0, pk.selPos < 0 ? 0 : pk.selPos + delta));
    const box = $("#vlist");
    if (pos * ROW_H < box.scrollTop) box.scrollTop = pos * ROW_H;
    else if ((pos + 1) * ROW_H > box.scrollTop + box.clientHeight) box.scrollTop = (pos + 1) * ROW_H - box.clientHeight;
    const row = pk.pages.get(Math.floor(pos / PAGE))?.[pos % PAGE];
    if (row) pkSelect(pos, row);
    else pkRender();
  }

  function goToFlow(idx) {
    if (idx == null || !state.byIdx.has(idx)) {
      toast("Este paquete no pertenece a ninguna conversación reconocida.", "info");
      return;
    }
    state.storyFilter = null;
    const r = state.byIdx.get(idx);
    if (r.flow.is_background_noise && !state.showNoise) {
      state.showNoise = true;
      $("#noise-toggle").checked = true;
    }
    if (state.show === "importante" && r.explain.level === "ok") {
      state.show = "todo";
      syncChips();
    }
    switchView("flows");
    select(idx);
  }

  // ------------------------------------------------------------ estadísticas

  const PROTO_ABOUT = {
    DNS: "traducir nombres a direcciones",
    TLS: "conexiones cifradas (HTTPS y otras)",
    HTTP: "web sin cifrar",
    SSH: "acceso remoto seguro",
    NTP: "poner el reloj en hora",
    DHCP: "pedir una dirección IP",
    TCP: "otras conexiones TCP",
    UDP: "otros envíos UDP",
    ICMP: "mensajes de control (ping…)",
    OTRO: "otros protocolos",
  };
  const SCOPE_ES = { local: "Tu red", internet: "Internet", grupo: "Grupo" };

  async function loadStats({ quiet = false } = {}) {
    const box = $("#stats");
    state.lastStats = Date.now();
    const q = viewQuery();
    if (!quiet) box.style.opacity = box.childElementCount ? "0.6" : "";
    let st;
    let tl;
    try {
      [st, tl] = await Promise.all([api(`/api/stats${q ? "?" + q : ""}`), api(`/api/timeline${q ? "?" + q : ""}`)]);
    } catch (err) {
      box.style.opacity = "";
      if (!quiet) toast(`No se pudieron calcular las estadísticas: ${err.message}`);
      return;
    }
    box.style.opacity = "";
    const scrollTop = box.scrollTop;
    renderStats(box, st, tl);
    box.scrollTop = scrollTop;
  }

  function renderStats(box, st, tl) {
    clear(box);
    const ses = state.session;
    const span = ses.first_seen != null && ses.last_seen != null ? ses.last_seen - ses.first_seen : 0;
    const tile = (label, value, detail) =>
      h("div", { class: "tile" }, h("span", { class: "l" }, label), h("span", { class: "v" }, value), detail ? h("span", { class: "d" }, detail) : null);
    const filtered = !!viewQuery();
    box.append(
      h(
        "div",
        { class: "tiles" },
        tile("Paquetes", nf.format(st.total.packets), filtered ? "con los filtros actuales" : null),
        tile("Datos", fmtBytes(st.total.bytes)),
        tile("Conversaciones", nf.format(st.total.flows)),
        tile("Equipos", nf.format(st.endpoints_total), "direcciones distintas"),
        tile("Servicios", nf.format(st.services_total), "puertos de destino"),
        tile("Duración", span > 0 ? fmtDuration(span) : "—"),
      ),
    );

    // Actividad en el tiempo: una sola serie (paquetes o datos), nunca dos ejes.
    const measure = state.measure;
    const values = measure === "bytes" ? tl.bytes : tl.packets;
    const chartBox = h("div", { class: "card-body" });
    const seg = h(
      "div",
      { class: "segmented small", role: "group", "aria-label": "Qué medir" },
      [
        ["packets", "Paquetes"],
        ["bytes", "Datos"],
      ].map(([m, label]) =>
        h(
          "button",
          {
            type: "button",
            "aria-pressed": String(measure === m),
            onclick: () => {
              state.measure = m;
              pref("measure", m);
              loadStats({ quiet: true });
            },
          },
          label,
        ),
      ),
    );
    box.append(
      h(
        "section",
        { class: "card wide" },
        h(
          "div",
          { class: "card-head" },
          h("h2", null, measure === "bytes" ? "Datos en el tiempo" : "Paquetes en el tiempo"),
          h("span", { class: "sub" }, tl.packets.length ? `Cada barra son ${fmtDuration(tl.bucket_micros)}. Los picos son ráfagas de actividad.` : ""),
          seg,
        ),
        chartBox,
      ),
    );
    const fmtMeasure = measure === "bytes" ? fmtBytes : (v) => plural(v, "paquete", "paquetes");
    drawColumns(chartBox, values, tl, fmtMeasure);
    const busiest = values
      .map((v, i) => [v, i])
      .filter(([v]) => v > 0)
      .sort((a, b) => b[0] - a[0] || a[1] - b[1])
      .slice(0, 50)
      .sort((a, b) => a[1] - b[1]);
    if (busiest.length) {
      chartBox.append(
        h(
          "details",
          { class: "as-table" },
          h("summary", null, "Ver los datos como tabla"),
          h(
            "table",
            { class: "grid" },
            h("thead", null, h("tr", null, h("th", null, h("span", null, "Desde")), h("th", null, h("span", null, "Hasta")), h("th", { class: "num" }, h("span", null, measure === "bytes" ? "Datos" : "Paquetes")))),
            h(
              "tbody",
              null,
              busiest.map(([v, i]) => {
                const from = tl.start_micros + i * tl.bucket_micros;
                return h("tr", null, h("td", { class: "time" }, fmtTime(from)), h("td", { class: "time" }, fmtTime(from + tl.bucket_micros)), h("td", { class: "num" }, fmtMeasure(v)));
              }),
            ),
          ),
          values.filter((v) => v > 0).length > busiest.length ? h("p", { class: "sub" }, "Solo los 50 intervalos con más actividad.") : null,
        ),
      );
    }

    // Protocolos.
    const maxP = Math.max(1, ...st.protocols.map((p) => p.bytes));
    const bars = h("div", { class: "hbars" });
    for (const p of st.protocols) {
      const about = PROTO_ABOUT[p.name] || "";
      const pct = st.total.bytes ? Math.round((p.bytes / st.total.bytes) * 100) : 0;
      bars.append(
        h(
          "div",
          {
            class: "hbar",
            tabindex: "0",
            role: "button",
            title: `${p.name}: ${about}. Pulsa para ver solo esto.`,
            onclick: () => applyAsFilter(exprProto(p.name)),
            onkeydown: (e) => e.key === "Enter" && applyAsFilter(exprProto(p.name)),
            oncontextmenu: (e) => {
              e.preventDefault();
              openMenu(e.clientX, e.clientY, [
                { title: p.name },
                { label: `Ver solo ${p.name}`, expr: exprProto(p.name) },
                { label: `Ocultar ${p.name}`, expr: `!(${exprProto(p.name)})` },
              ]);
            },
          },
          h("span", { class: "name" }, h("b", null, p.name), about ? h("small", null, about) : null),
          h("span", { class: "track" }, h("span", { class: "fill", style: { width: `${(p.bytes / maxP) * 100}%` } })),
          h("span", { class: "val" }, h("b", null, fmtBytes(p.bytes)), ` · ${pct} % · ${plural(p.flows, "conv.", "conv.")}`),
        ),
      );
    }
    box.append(
      h(
        "section",
        { class: "card" },
        h("div", { class: "card-head" }, h("h2", null, "Protocolos"), h("span", { class: "sub" }, "Qué tipo de tráfico hay, por volumen de datos")),
        h("div", { class: "card-body" }, st.protocols.length ? bars : h("p", { class: "chart-empty" }, "Sin datos")),
      ),
    );

    // Servicios.
    const svc = h("tbody");
    for (const sv of st.services) {
      const expr = exprService(sv.port, sv.transport);
      svc.append(
        h(
          "tr",
          {
            class: sv.level !== "ok" ? sv.level : null,
            title: "Pulsa para ver solo este servicio",
            onclick: () => applyAsFilter(expr),
            oncontextmenu: (e) => {
              e.preventDefault();
              openMenu(e.clientX, e.clientY, [
                { title: `Puerto ${sv.port}/${sv.transport}` },
                { label: "Ver solo este servicio", expr },
                { label: "Ocultar este servicio", expr: `!(${expr})` },
              ]);
            },
          },
          h("td", null, dot(sv.level)),
          h("td", { class: "mono" }, `${sv.port}/${sv.transport.toLowerCase()}`),
          h("td", null, sv.about ? rich(sv.about) : h("span", { class: "sub" }, "desconocido")),
          h("td", { class: "num" }, nf.format(sv.flows)),
          h("td", { class: "num" }, fmtBytes(sv.bytes)),
        ),
      );
    }
    box.append(
      h(
        "section",
        { class: "card" },
        h(
          "div",
          { class: "card-head" },
          h("h2", null, "Servicios"),
          h("span", { class: "sub" }, st.services_total > st.services.length ? `Los ${st.services.length} más usados de ${nf.format(st.services_total)}` : "A qué puertos se conectan los equipos"),
        ),
        h(
          "div",
          { class: "card-body flush" },
          h("table", { class: "grid" }, h("thead", null, h("tr", null, ["", "Puerto", "Qué es", "Conv.", "Datos"].map((c, i) => h("th", { class: i >= 3 ? "num" : null }, h("span", null, c))))), svc),
        ),
      ),
    );

    // Equipos (endpoints).
    const maxE = Math.max(1, ...st.endpoints.map((e) => e.bytes_out + e.bytes_in));
    const eps = h("tbody");
    for (const e of st.endpoints) {
      const total = e.bytes_out + e.bytes_in;
      eps.append(
        h(
          "tr",
          {
            class: e.level !== "ok" ? e.level : null,
            title: "Pulsa para ver solo lo de este equipo",
            onclick: () => applyAsFilter(exprHost(e.ip)),
            oncontextmenu: (ev) => {
              ev.preventDefault();
              openMenu(ev.clientX, ev.clientY, hostMenu(e.ip, e.domain));
            },
          },
          h("td", null, dot(e.level)),
          h(
            "td",
            null,
            e.host && e.host.short ? h("div", { class: "host-name" }, e.host.short, " ", renameButton(e.ip)) : null,
            h("div", { class: e.host && e.host.short ? "mono sub" : "mono" }, e.ip, e.host && e.host.short ? null : [" ", renameButton(e.ip)]),
            e.host && hostFacts(e.host).length
              ? h("div", { class: "sub" }, hostFacts(e.host).slice(0, 2).join(" · "))
              : e.domain
                ? h("div", { class: "sub", title: e.domain }, e.domain)
                : null,
          ),
          h("td", null, h("span", { class: `scope ${e.scope}` }, SCOPE_ES[e.scope] || e.scope)),
          h("td", { class: "num" }, nf.format(e.flows)),
          h("td", { class: "num" }, nf.format(e.peers)),
          h("td", { class: "num" }, fmtBytes(e.bytes_out)),
          h("td", { class: "num" }, fmtBytes(e.bytes_in)),
          h("td", { class: "num" }, fmtBytes(total), h("span", { class: "inline-bar", style: { width: `${(total / maxE) * 100}%` } })),
        ),
      );
    }
    const epHead = ["", "Equipo", "Dónde", "Conv.", "Con cuántos", "Envió", "Recibió", "Total"];
    box.append(
      h(
        "section",
        { class: "card wide" },
        h(
          "div",
          { class: "card-head" },
          h("h2", null, "Equipos que más hablan"),
          h("span", { class: "sub" }, st.endpoints_total > st.endpoints.length ? `Los ${st.endpoints.length} primeros de ${nf.format(st.endpoints_total)}` : "Ordenados por datos enviados y recibidos"),
        ),
        h(
          "div",
          { class: "card-body flush" },
          h("table", { class: "grid" }, h("thead", null, h("tr", null, epHead.map((c, i) => h("th", { class: i >= 3 ? "num" : null }, h("span", null, c))))), eps),
        ),
      ),
    );
  }

  /** Gráfica de columnas de una serie, con tooltip por barra. */
  function drawColumns(box, values, tl, fmtVal) {
    if (!values.length || values.every((v) => v === 0)) {
      box.append(h("p", { class: "chart-empty" }, "Sin actividad que mostrar."));
      return;
    }
    const W = Math.max(320, box.clientWidth - 28 || 800);
    const H = 200;
    const pad = { l: 46, r: 8, t: 8, b: 22 };
    const iw = W - pad.l - pad.r;
    const ih = H - pad.t - pad.b;
    const maxV = Math.max(...values);
    const step = niceStep(maxV / 4);
    const top = Math.max(step, Math.ceil(maxV / step) * step);
    const y = (v) => pad.t + ih - (v / top) * ih;
    const fmtTick = fmtVal === fmtBytes ? fmtBytes : (v) => compact.format(v);
    const svg = s("svg", { class: "chart", viewBox: `0 0 ${W} ${H}`, role: "img", "aria-label": "Actividad en el tiempo" });
    for (let v = 0; v <= top + 1e-9; v += step) {
      svg.append(
        s("line", { class: v === 0 ? "baseline" : "gridline", x1: pad.l, x2: W - pad.r, y1: y(v), y2: y(v) }),
        s("text", { x: pad.l - 6, y: y(v) + 4, "text-anchor": "end" }, fmtTick(v)),
      );
    }
    const slot = iw / values.length;
    const bw = Math.max(1, Math.min(24, slot - 2));
    values.forEach((v, i) => {
      const x = pad.l + i * slot + (slot - bw) / 2;
      const from = tl.start_micros + i * tl.bucket_micros;
      const hit = s("rect", { class: "hit", x: pad.l + i * slot, y: pad.t, width: slot, height: ih, tabindex: "-1" });
      svg.append(hit);
      if (v > 0) {
        const bh = Math.max(1, (v / top) * ih);
        const r = Math.min(4, bw / 2, bh);
        const x2 = x + bw;
        const yb = pad.t + ih;
        const yt = yb - bh;
        const bar = s("path", {
          class: "bar",
          d: `M${x},${yb}V${yt + r}Q${x},${yt} ${x + r},${yt}H${x2 - r}Q${x2},${yt} ${x2},${yt + r}V${yb}Z`,
        });
        svg.append(bar);
      } else svg.append(s("g"));
      const tip = () =>
        showTipAt(
          hit.getBoundingClientRect(),
          h("span", { class: "tv" }, fmtVal(v)),
          `${fmtTime(from)} – ${fmtTime(from + tl.bucket_micros)}`,
        );
      hit.addEventListener("pointerenter", tip);
      hit.addEventListener("pointerleave", hideTip);
    });
    // Eje X: inicio, mitad y fin, en hora de reloj.
    const end = tl.start_micros + values.length * tl.bucket_micros;
    [
      [pad.l, "start", tl.start_micros],
      [pad.l + iw / 2, "middle", (tl.start_micros + end) / 2],
      [W - pad.r, "end", end],
    ].forEach(([x, anchor, t]) => svg.append(s("text", { x, y: H - 6, "text-anchor": anchor }, fmtTime(t))));
    box.append(svg);
  }

  function niceStep(raw) {
    if (raw <= 1) return 1;
    const mag = 10 ** Math.floor(Math.log10(raw));
    const n = raw / mag;
    return (n <= 1 ? 1 : n <= 2 ? 2 : n <= 2.5 ? 2.5 : n <= 5 ? 5 : 10) * mag;
  }

  // ------------------------------------------------------------ menú contextual

  const menu = $("#ctx");

  function openMenu(x, y, items) {
    clear(menu);
    for (const it of items) {
      if (it === "-") menu.append(h("hr"));
      else if (it.title) menu.append(h("div", { class: "ctx-title" }, it.title));
      else {
        menu.append(
          h(
            "button",
            {
              type: "button",
              role: "menuitem",
              title: it.expr || null,
              onclick: () => {
                closeMenu();
                if (it.expr) applyAsFilter(it.expr);
                else it.action();
              },
            },
            h("span", null, it.label),
            it.hint ? h("code", null, it.hint) : null,
          ),
        );
      }
    }
    if (items.some((it) => it.expr)) {
      const cb = h("input", {
        type: "checkbox",
        onchange: (e) => {
          state.combine = e.target.checked;
          pref("combine", state.combine ? "1" : "0");
        },
      });
      cb.checked = state.combine;
      menu.append(h("hr"), h("label", { title: "Si está marcado, se suma al filtro que ya tienes (con «y»)" }, cb, "Añadir al filtro actual"));
    }
    menu.hidden = false;
    const mw = menu.offsetWidth;
    const mh = menu.offsetHeight;
    menu.style.left = `${Math.min(x, window.innerWidth - mw - 6)}px`;
    menu.style.top = `${Math.min(y, window.innerHeight - mh - 6)}px`;
    const firstBtn = menu.querySelector("button");
    if (firstBtn) firstBtn.focus({ preventScroll: true });
  }

  function closeMenu() {
    menu.hidden = true;
  }

  async function copy(text) {
    try {
      await navigator.clipboard.writeText(text);
      toast(`Copiado: ${text.length > 60 ? text.slice(0, 60) + "…" : text}`, "info");
    } catch {
      toast("No se pudo copiar al portapapeles.");
    }
  }

  function hostMenu(ip, domain) {
    const hst = hostOf(ip);
    const items = [
      { title: [hst && hst.short, ip, domain].filter(Boolean).join(" · ") },
      { label: "Ver solo este equipo", expr: exprHost(ip) },
      { label: "Ocultar este equipo", expr: exprNotHost(ip) },
      "-",
    ];
    if (isLanIp(ip)) items.push({ label: hst && hst.nickname ? "Cambiar su nombre…" : "Ponerle nombre…", action: () => openNickDialog(ip) });
    items.push({ label: "Copiar la dirección", action: () => copy(ip) });
    return items;
  }

  function flowMenu(r) {
    const f = r.flow;
    const items = [
      { title: "Filtrar" },
      { label: "Ver solo esta conversación", expr: exprConv(f) },
      { label: `Ver solo ${f.src_ip}`, hint: "origen", expr: exprHost(f.src_ip) },
      { label: `Ver solo ${f.dst_ip}`, hint: f.resolved_domain ? f.resolved_domain.slice(0, 28) : "destino", expr: exprHost(f.dst_ip) },
      { label: `Ocultar ${f.src_ip}`, expr: exprNotHost(f.src_ip) },
      { label: `Ocultar ${f.dst_ip}`, expr: exprNotHost(f.dst_ip) },
    ];
    if (hasPorts(f)) items.push({ label: `Ver solo conexiones al puerto ${f.dst_port}`, expr: exprService(f.dst_port, transportName(f)) });
    if (r.proto !== "TCP" && r.proto !== "UDP") items.push({ label: `Ver solo ${r.proto}`, expr: exprProto(r.proto) });
    items.push(
      "-",
      { label: "Ver sus paquetes", action: () => (switchView("flows"), select(r.idx), setTab("packets")) },
      { label: "Ver lo que se dijeron", action: () => (switchView("flows"), select(r.idx), setTab("stream")) },
      "-",
    );
    for (const ip of [f.src_ip, f.dst_ip]) {
      if (isLanIp(ip)) items.push({ label: `Ponerle nombre a ${(hostOf(ip) && hostOf(ip).short) || ip}…`, action: () => openNickDialog(ip) });
    }
    items.push(
      "-",
      { label: "Copiar origen", hint: ep(f, "src"), action: () => copy(ep(f, "src")) },
      { label: "Copiar destino", hint: ep(f, "dst"), action: () => copy(ep(f, "dst")) },
      { label: "Copiar como filtro", action: () => copy(exprConv(f)) },
    );
    return items;
  }

  function packetMenu(row) {
    const r = row.flow != null ? state.byIdx.get(row.flow) : null;
    const items = [{ title: `Paquete n.º ${row.n}` }];
    if (r) {
      items.push({ label: "Ir a su conversación", action: () => goToFlow(row.flow) }, "-");
      items.push(...flowMenu(r).filter((it) => it === "-" || it.expr || it.title));
    }
    items.push("-", { label: "Copiar el resumen", action: () => copy(`${row.n}\t${row.src}\t${row.dst}\t${row.protocol}\t${row.len}\t${row.summary}`) });
    return items;
  }

  function applyAsFilter(expr) {
    const cur = state.filter.trim();
    const next = state.combine && cur ? `(${cur}) && ${expr}` : expr;
    $("#filter-input").value = next;
    applyFilter();
  }

  // ------------------------------------------------------------ carga y filtros

  async function loadFlows(filter) {
    const q = filter ? `?filter=${encodeURIComponent(filter)}` : "";
    const data = await api(`/api/flows${q}`);
    state.flows = data.flows;
    state.byIdx = new Map(data.flows.map((r) => [r.idx, r]));
    return data;
  }

  /** Captura nueva (archivo abierto o captura en vivo recién empezada). */
  async function loadAll() {
    state.session = await api("/api/session");
    const loaded = state.session.loaded;
    $("#welcome").hidden = loaded;
    renderToolbar();
    if (!loaded) {
      renderStatus();
      return;
    }
    state.cache.clear();
    state.storyFilter = null;
    state.selectedKey = null;
    state.packetSel = null;
    state.rowLimit = 2000;
    state.filter = "";
    state.pk.sel = null;
    state.pk.selPos = -1;
    $("#filter-input").value = "";
    setFilterError(null);
    const [stories, data] = await Promise.all([api("/api/stories"), loadFlows(""), loadHosts()]);
    state.stories = stories;
    if (data.truncated) toast(`Hay ${nf.format(data.total)} conversaciones: se muestran las primeras 10.000. Usa un filtro para acotar.`, "info");
    document.title = `${state.session.name} · soc-shark`;
    renderOverview();
    renderStories();
    renderStoryChip();
    renderTable();
    const first = state.stories.length ? state.stories[0].flows[0] : visibleFlows()[0] && visibleFlows()[0].idx;
    if (first != null) select(first);
    else renderDetail();
    clear($("#pk-detail")).append(h("p", { class: "placeholder" }, "Elige un paquete para ver sus capas y sus bytes."));
    if (state.view !== "flows") renderView();
    if (liveRunning()) startPolling();
  }

  /** Foto nueva de la captura en vivo: se refresca sin perder lo que miras.
   *  Los refrescos van en cola: el de "Detener" nunca se pierde. */
  let refreshChain = Promise.resolve();
  let pendingRefreshes = 0;
  function refresh(ses) {
    pendingRefreshes++;
    state.refreshing = true;
    refreshChain = refreshChain
      .then(() => doRefresh(ses))
      .finally(() => {
        if (--pendingRefreshes === 0) state.refreshing = false;
      });
    return refreshChain;
  }

  async function doRefresh(ses) {
    try {
      const [stories] = await Promise.all([api("/api/stories"), loadFlows(state.filter), loadHosts()]);
      state.session = ses;
      state.stories = stories;
      if (state.storyFilter) {
        const again = stories.find((st) => st.title === state.storyFilter.title);
        state.storyFilter.idx = new Set(again ? again.flows : []);
      }
      renderToolbar();
      renderOverview();
      renderStories();
      renderStoryChip();
      if (state.view === "flows") {
        const wrap = $("#table-wrap");
        const top = wrap.scrollTop;
        renderTable();
        wrap.scrollTop = top;
        const r = selectedRow();
        if (!state.selectedKey) {
          const first = visibleFlows()[0];
          if (first) select(first.idx);
        } else if (!r) renderDetail();
        else if (detailSig(r) !== state.detailSig) renderDetail({ soft: true });
      } else if (state.view === "packets") {
        state.pk.key = `${gen()}|${viewQuery()}`;
        state.pk.stale = state.pk.pages;
        state.pk.pages = new Map();
        if (state.pk.follow && liveRunning()) scrollToEnd();
        pkRender();
      } else if (state.view === "stats" && (Date.now() - state.lastStats > 2500 || !liveRunning())) {
        loadStats({ quiet: true });
      }
      renderStatus();
    } catch (err) {
      if (err.status !== 400) toast(`No se pudo actualizar: ${err.message}`);
    }
  }

  function setFilterError(err) {
    const input = $("#filter-input");
    const box = $("#filter-error");
    input.classList.toggle("invalid", !!err);
    box.textContent = err || "";
  }

  function rememberFilter(expr) {
    if (!expr) return;
    state.history = [expr, ...state.history.filter((x) => x !== expr)].slice(0, 15);
    pref("history", JSON.stringify(state.history));
    renderHistory();
  }

  function renderHistory() {
    const dl = clear($("#filter-history"));
    for (const x of state.history) dl.append(h("option", { value: x }));
  }

  async function applyFilter() {
    if (!state.session || !state.session.loaded) return;
    const expr = $("#filter-input").value.trim();
    try {
      await loadFlows(expr);
      state.filter = expr;
      setFilterError(null);
      $("#filter-input").classList.toggle("applied", !!expr);
      rememberFilter(expr);
      state.storyFilter = null;
      state.rowLimit = 2000;
      renderStoryChip();
      renderTable();
      if (!selectedRow() || !state.byIdx.has(selectedRow().idx)) {
        const first = visibleFlows()[0];
        state.selectedKey = null;
        if (first) select(first.idx);
        else renderDetail();
      }
      if (state.view !== "flows") renderView();
    } catch (err) {
      if (err.status === 400 && err.body) {
        const pos = err.body.pos;
        const where = pos >= expr.length ? "al final" : `en la posición ${pos + 1} («${expr.slice(pos, pos + 12)}»)`;
        setFilterError(`El filtro tiene un error ${where}: ${err.body.error}. Pulsa F1 para ver ejemplos.`);
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
      stopPolling();
      await api(`/api/open?name=${encodeURIComponent(file.name)}`, { method: "POST", body: file });
      await loadAll();
    } catch (err) {
      toast(`No se pudo abrir «${file.name}»: ${err.message}`);
    } finally {
      busy(null);
      $("#file-input").value = "";
    }
  }

  // ------------------------------------------------------------ captura en vivo

  // Pseudo-interfaces y adaptadores virtuales: existen, pero casi nunca son
  // "la red" que una persona quiere ver.
  const PSEUDO_RE = /pseudo-device|bluetooth|netfilter|d-bus|usbmon|usb bus|wan miniport|event tracing|etwdump|ciscodump|randpkt|sshdump|udpdump|wifidump/i;
  const VIRTUAL_RE = /virtual|vmware|virtualbox|hyper-v|vethernet|docker|tailscale|wireguard|zerotier|tap-windows|teredo|isatap|tunnel/i;
  const isLoopback = (i) => i.loopback || /^lo\d*$/.test(i.name) || /loopback/i.test(i.description || "");
  function ifaceGroup(i) {
    if (isLoopback(i)) return "loopback";
    const text = `${i.name} ${i.description || ""}`;
    if (i.name === "any" || PSEUDO_RE.test(text) || VIRTUAL_RE.test(text)) return "other";
    if (/^(ifb|veth|docker|br-|virbr|tun|tap|wg|utun|awdl|llw|anpi|gif|stf|bridge)/.test(i.name)) return "other";
    return "main";
  }
  const ifaceActive = (i) => (i.up || !("up" in i)) && i.connected !== false;
  function ifaceTitle(i) {
    if (i.name === "any") return "Todas las interfaces a la vez";
    return i.description || i.name;
  }
  function ifaceLabel(name) {
    const i = state.ifaces.find((x) => x.name === name);
    return (i && ifaceTitle(i)) || pref("iface-desc-" + name) || name;
  }

  async function openLiveDialog() {
    const dlg = $("#live-dlg");
    const list = clear($("#iface-list"));
    const err = $("#live-error");
    err.hidden = true;
    $("#live-go").disabled = true;
    $("#live-replace").hidden = !(state.session && state.session.loaded && !liveRunning());
    $("#bpf-input").value = pref("bpf") || "";
    list.append(h("p", { class: "muted" }, "Buscando interfaces…"));
    if (!dlg.open) dlg.showModal();
    let ifaces;
    try {
      ifaces = await api("/api/live/ifaces");
    } catch (e) {
      clear(list);
      err.hidden = false;
      err.textContent = `No se puede capturar en vivo en este equipo: ${e.message}`;
      return;
    }
    state.ifaces = ifaces;
    clear(list);
    if (!ifaces.length) {
      err.hidden = false;
      err.textContent = "No se encontró ninguna interfaz. En Windows instala Npcap (npcap.com); en Linux/macOS ejecuta soc-shark con permisos de captura (sudo).";
      return;
    }
    // Tu red primero (las conectadas y con dirección, arriba); después este
    // mismo equipo; el resto, plegado como "avanzado".
    const rank = (i) => (ifaceActive(i) ? 0 : 2) + (i.addresses && i.addresses.length ? 0 : 1);
    const groups = { main: [], loopback: [], other: [] };
    for (const i of ifaces) groups[ifaceGroup(i)].push(i);
    groups.main.sort((a, b) => rank(a) - rank(b) || !!b.wireless - !!a.wireless);
    const last = pref("iface");
    const pick = ifaces.find((i) => i.name === last) || groups.main.find(ifaceActive) || groups.main[0] || groups.loopback[0] || ifaces[0];

    const row = (i) => {
      const radio = h("input", { type: "radio", name: "iface", value: i.name });
      radio.checked = i === pick;
      const off = !ifaceActive(i);
      const facts = [];
      if (i.wireless) facts.push("inalámbrica");
      if (off) facts.push("sin conexión");
      else if (i.connected === true) facts.push("conectada");
      facts.push(...(i.addresses || []).slice(0, 2));
      if (isLoopback(i)) facts.push("programas que hablan entre sí dentro del equipo");
      return h(
        "label",
        { class: `iface${off ? " off" : ""}`, title: i.name },
        radio,
        h("b", null, ifaceTitle(i)),
        h("span", { class: "iface-facts" }, facts.join(" · ") || (i.description ? i.name : "")),
      );
    };
    const section = (title, items) => [h("div", { class: "iface-group" }, title), items.map(row)];
    if (groups.main.length) list.append(...section("Tu red", groups.main).flat());
    else list.append(h("p", { class: "muted" }, "No se ve ninguna tarjeta de red (Wi-Fi o cable). Revisa las de «Otras»."));
    if (groups.loopback.length) list.append(...section("Este mismo equipo", groups.loopback).flat());
    if (groups.other.length) {
      list.append(
        h(
          "details",
          { class: "iface-more", open: groups.other.includes(pick) ? true : null },
          h("summary", null, `Otras interfaces (${groups.other.length}) · avanzado`),
          groups.other.map(row),
        ),
      );
    }
    $("#live-go").disabled = false;
  }

  async function startLive() {
    const radio = document.querySelector('#iface-list input[name="iface"]:checked');
    if (!radio) return;
    const iface = radio.value;
    const bpf = $("#bpf-input").value.trim();
    const err = $("#live-error");
    err.hidden = true;
    $("#live-go").disabled = true;
    try {
      await api(`/api/live/start?iface=${encodeURIComponent(iface)}${bpf ? `&bpf=${encodeURIComponent(bpf)}` : ""}`, { method: "POST" });
    } catch (e) {
      err.hidden = false;
      err.textContent = e.message;
      $("#live-go").disabled = false;
      return;
    }
    pref("iface", iface);
    pref("bpf", bpf);
    const chosen = state.ifaces.find((x) => x.name === iface);
    if (chosen) pref("iface-desc-" + iface, ifaceTitle(chosen));
    $("#live-dlg").close();
    state.pk.follow = true;
    $("#follow-toggle").checked = true;
    await loadAll();
  }

  async function stopLive() {
    $("#stop-btn").disabled = true;
    try {
      stopPolling();
      const ses = await api("/api/live/stop", { method: "POST" });
      await refresh(ses);
      toast("Captura detenida. Puedes revisarla con calma o guardarla como .pcap.", "info");
    } catch (e) {
      toast(`No se pudo detener: ${e.message}`);
    } finally {
      $("#stop-btn").disabled = false;
      renderToolbar();
    }
  }

  function startPolling() {
    if (state.polling) return;
    state.polling = setInterval(poll, 1000);
  }

  function stopPolling() {
    clearInterval(state.polling);
    state.polling = null;
  }

  async function poll() {
    if (state.refreshing) return; // el anterior aún no acabó
    let ses;
    try {
      ses = await api("/api/session");
    } catch {
      return; // un fallo suelto no corta el refresco
    }
    if (!ses.loaded || !ses.live) {
      stopPolling();
      return;
    }
    const changed = ses.generation !== gen();
    if (!changed) {
      state.session = ses;
      renderStatus();
      return;
    }
    await refresh(ses);
    if (!ses.live.running) {
      stopPolling();
      if (ses.live.error) toast(`La captura en vivo se detuvo: ${ses.live.error}`);
    }
  }

  // ------------------------------------------------------------ guardar

  async function save() {
    if (!state.session || !state.session.loaded || !state.session.packets) return;
    let res;
    try {
      res = await fetch("/api/save.pcap", { headers: { "X-Socshark-Token": TOKEN } });
      if (!res.ok) throw new Error((await res.json().catch(() => null))?.error || `Error ${res.status}`);
    } catch (e) {
      toast(`No se pudo guardar: ${e.message}`);
      return;
    }
    const blob = await res.blob();
    const m = /filename="([^"]+)"/.exec(res.headers.get("Content-Disposition") || "");
    const name = m ? m[1] : "captura.pcap";
    const url = URL.createObjectURL(blob);
    const a = h("a", { href: url, download: name, hidden: true });
    document.body.append(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 30000);
    toast(`Guardado «${name}» (${fmtBytes(blob.size)}) en tu carpeta de descargas. Se abre también con Wireshark.`, "info");
  }

  // ------------------------------------------------------------ barra de herramientas y de estado

  function renderToolbar() {
    const running = liveRunning();
    $("#live-btn").hidden = running;
    $("#stop-btn").hidden = !running;
    const ses = state.session;
    $("#save-btn").disabled = !(ses && ses.loaded && ses.packets > 0);
    $("#follow-wrap").hidden = !running;
  }

  function renderStatus() {
    const bar = clear($("#statusbar"));
    const ses = state.session;
    const item = (...kids) => h("span", null, ...kids);
    if (!ses || !ses.loaded) {
      bar.append(item("Sin captura · abre un archivo o empieza a capturar en vivo"), item(`soc-shark ${ses ? ses.version : ""}`));
      return;
    }
    const live = ses.live;
    if (live) {
      const name = ifaceLabel(live.iface);
      if (live.running) {
        bar.append(item(h("i", { class: "live-dot" }), h("b", null, "En vivo"), ` · ${name} · ${fmtElapsed(Date.now() * 1000 - live.started_micros)}`));
      } else if (live.error) {
        bar.append(item({ class: "err" }, h("i", { class: "live-dot off" }), `Captura detenida por un error · ${name}`));
      } else {
        bar.append(item(h("i", { class: "live-dot off" }), `Captura en vivo detenida · ${name}`));
      }
    } else {
      bar.append(item("Archivo: ", h("b", null, ses.name)));
    }
    bar.append(item("Paquetes: ", h("b", null, nf.format(ses.packets))));
    if (state.view === "packets") bar.append(item("Mostrados: ", h("b", null, nf.format(state.pk.total))));
    else bar.append(item("Conversaciones: ", h("b", null, nf.format(state.visibleCount)), ` de ${nf.format(ses.flows)}`));
    if (live && live.kernel_drop > 0) {
      bar.append(
        h(
          "span",
          { class: "warn", title: "El equipo no dio abasto y el sistema descartó paquetes antes de que soc-shark los viera. Un filtro de captura ayuda." },
          `Perdidos por el sistema: ${nf.format(live.kernel_drop)}`,
        ),
      );
    }
    if (live && live.bpf) bar.append(item("Captura: ", h("code", null, live.bpf)));
    bar.append(item("Filtro: ", state.filter ? h("code", null, state.filter) : "ninguno"));
    bar.append(item(`soc-shark ${ses.version}`));
  }

  // ------------------------------------------------------------ vistas y paneles

  function switchView(view) {
    if (!["flows", "packets", "stats"].includes(view)) view = "flows";
    state.view = view;
    pref("view", view);
    for (const b of $$(".views [role=tab]")) b.setAttribute("aria-selected", String(b.dataset.view === view));
    $("#view-flows").hidden = view !== "flows";
    $("#view-packets").hidden = view !== "packets";
    $("#view-stats").hidden = view !== "stats";
    renderStoryChip();
    renderView();
  }

  function renderView() {
    if (!state.session || !state.session.loaded) return;
    if (state.view === "flows") renderTable();
    else if (state.view === "packets") {
      if (state.pk.key !== `${gen()}|${viewQuery()}`) pkReset();
      else pkRender();
    } else loadStats();
    renderStatus();
  }

  function initSplitters() {
    const ws = $("#workspace");
    const side = Number(pref("side-w"));
    if (side) ws.style.setProperty("--side-w", `${side}px`);
    for (const v of $$(".split-view")) {
      const top = Number(pref(`top-${v.id}`));
      if (top) v.style.setProperty("--top", `${top}%`);
    }
    for (const sp of $$(".splitter")) {
      const vertical = sp.classList.contains("v");
      const view = sp.closest(".split-view");
      const apply = (val) => {
        if (vertical) {
          const w = Math.round(Math.min(Math.max(200, val), ws.clientWidth * 0.5));
          ws.style.setProperty("--side-w", `${w}px`);
          pref("side-w", w);
        } else {
          const pct = Math.min(85, Math.max(15, val));
          view.style.setProperty("--top", `${pct.toFixed(1)}%`);
          pref(`top-${view.id}`, pct.toFixed(1));
        }
      };
      const current = () =>
        vertical ? $("#sidebar").getBoundingClientRect().width : (view.firstElementChild.getBoundingClientRect().height / view.clientHeight) * 100;
      sp.addEventListener("pointerdown", (e) => {
        e.preventDefault();
        sp.setPointerCapture(e.pointerId);
        sp.classList.add("dragging");
        document.body.classList.add(vertical ? "dragging-v" : "dragging-h");
        const move = (ev) => {
          if (vertical) apply(ev.clientX - ws.getBoundingClientRect().left - 8);
          else {
            const r = view.getBoundingClientRect();
            apply(((ev.clientY - r.top) / r.height) * 100);
          }
        };
        const up = () => {
          sp.classList.remove("dragging");
          document.body.classList.remove("dragging-v", "dragging-h");
          sp.removeEventListener("pointermove", move);
          sp.removeEventListener("pointerup", up);
          if (state.view === "packets") pkRender();
          if (state.view === "stats") loadStats({ quiet: true });
        };
        sp.addEventListener("pointermove", move);
        sp.addEventListener("pointerup", up);
      });
      sp.addEventListener("keydown", (e) => {
        const d = { ArrowLeft: -1, ArrowUp: -1, ArrowRight: 1, ArrowDown: 1 }[e.key];
        if (!d) return;
        e.preventDefault();
        apply(current() + d * (vertical ? 16 : 3));
      });
      sp.addEventListener("dblclick", () => {
        if (vertical) {
          ws.style.removeProperty("--side-w");
          pref("side-w", "");
        } else {
          view.style.removeProperty("--top");
          pref(`top-${view.id}`, "");
        }
      });
    }
  }

  function toggleSidebar(show) {
    const ws = $("#workspace");
    const on = show ?? ws.classList.contains("no-side");
    ws.classList.toggle("no-side", !on);
    $("#side-btn").setAttribute("aria-pressed", String(on));
    pref("side", on ? "1" : "0");
    if (state.view === "stats") loadStats({ quiet: true });
  }

  function setMode(mode) {
    state.mode = mode;
    pref("mode", mode);
    for (const b of $$(".segmented[aria-label='Nivel de detalle'] button")) b.setAttribute("aria-pressed", String(b.dataset.mode === mode));
    if (!COLUMNS[mode === "experto" ? "experto" : "simple"].some((c) => c.key === state.sort.key)) state.sort = { key: "time", dir: 1 };
    renderTable();
  }

  function syncChips() {
    for (const c of $$(".chip[data-show]")) c.setAttribute("aria-pressed", String(c.dataset.show === state.show));
  }

  function effectiveTheme() {
    const t = document.documentElement.dataset.theme;
    if (t) return t;
    return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  }

  // ------------------------------------------------------------ ayuda

  const EXAMPLES = [
    ["flow.risk >= 30", "lo que tiene algo de riesgo"],
    ["ip.addr == 192.168.1.30", "todo lo de ese equipo (como origen o destino)"],
    ["!(ip.addr == 192.168.1.1)", "todo menos ese equipo"],
    ["tcp.port == 443", "conexiones a web segura (HTTPS)"],
    ['dns.qname contains "google"', "consultas DNS que mencionan google"],
    ['proto == "HTTP"', "web sin cifrar"],
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
    const pickFile = () => $("#file-input").click();
    $("#open-btn").addEventListener("click", pickFile);
    $("#welcome-open").addEventListener("click", pickFile);
    $("#live-btn").addEventListener("click", openLiveDialog);
    $("#welcome-live").addEventListener("click", openLiveDialog);
    $("#stop-btn").addEventListener("click", stopLive);
    $("#save-btn").addEventListener("click", save);
    $("#file-input").addEventListener("change", (e) => openFile(e.target.files[0]));
    $("#live-form").addEventListener("submit", (e) => {
      e.preventDefault();
      if (!$("#live-go").disabled) startLive();
    });
    for (const b of $$("#live-dlg [data-close]")) b.addEventListener("click", () => $("#live-dlg").close());
    for (const b of $$("#nick-dlg [data-close]")) b.addEventListener("click", () => $("#nick-dlg").close());
    $("#nick-form").addEventListener("submit", (e) => {
      e.preventDefault();
      saveNick($("#nick-input").value);
    });
    $("#nick-remove").addEventListener("click", () => saveNick(""));
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
      pref("noise", state.showNoise ? "1" : "0");
      renderView();
    });
    for (const c of $$(".chip[data-show]")) {
      c.addEventListener("click", () => {
        state.show = c.dataset.show;
        state.storyFilter = null;
        syncChips();
        renderStoryChip();
        renderView();
      });
    }
    for (const b of $$(".views [role=tab]")) b.addEventListener("click", () => switchView(b.dataset.view));
    for (const b of $$(".segmented[aria-label='Nivel de detalle'] button")) b.addEventListener("click", () => setMode(b.dataset.mode));
    for (const b of $$(".tabs [role=tab]")) b.addEventListener("click", () => setTab(b.dataset.tab));
    $("#theme-btn").addEventListener("click", () => {
      const next = effectiveTheme() === "dark" ? "light" : "dark";
      document.documentElement.dataset.theme = next;
      pref("theme", next);
    });
    $("#side-btn").addEventListener("click", () => toggleSidebar());
    $("#help-btn").addEventListener("click", () => $("#help").showModal());
    $("#follow-toggle").addEventListener("change", (e) => {
      state.pk.follow = e.target.checked;
      if (state.pk.follow) {
        scrollToEnd();
        pkRender();
      }
    });

    const vlist = $("#vlist");
    let raf = 0;
    vlist.addEventListener("scroll", () => {
      if (!programmaticScroll && state.pk.follow && liveRunning()) {
        const atEnd = vlist.scrollTop + vlist.clientHeight >= vlist.scrollHeight - ROW_H;
        if (!atEnd) {
          state.pk.follow = false;
          $("#follow-toggle").checked = false;
        }
      }
      programmaticScroll = false;
      cancelAnimationFrame(raf);
      raf = requestAnimationFrame(pkRender);
    });
    new ResizeObserver(() => state.view === "packets" && pkRender()).observe(vlist);

    let resizeTimer = 0;
    window.addEventListener("resize", () => {
      clearTimeout(resizeTimer);
      resizeTimer = setTimeout(() => state.view === "stats" && state.session?.loaded && loadStats({ quiet: true }), 250);
    });

    document.addEventListener("pointerdown", (e) => {
      if (!menu.hidden && !menu.contains(e.target)) closeMenu();
    });
    window.addEventListener("blur", closeMenu);
    document.addEventListener("scroll", closeMenu, true);

    document.addEventListener("keydown", (e) => {
      const typing = e.target.closest && e.target.closest("input, select, textarea");
      const dialogOpen = document.querySelector("dialog[open]");
      const ctrl = e.ctrlKey || e.metaKey;
      if (!menu.hidden) {
        const items = [...menu.querySelectorAll("button")];
        const i = items.indexOf(document.activeElement);
        if (e.key === "Escape") {
          e.preventDefault();
          closeMenu();
        } else if (e.key === "ArrowDown" || e.key === "ArrowUp") {
          e.preventDefault();
          items[(i + (e.key === "ArrowDown" ? 1 : items.length - 1)) % items.length]?.focus();
        }
        return;
      }
      if (e.key === "F1") {
        e.preventDefault();
        if (!dialogOpen) $("#help").showModal();
      } else if (dialogOpen) {
        return;
      } else if (ctrl && e.key.toLowerCase() === "o") {
        e.preventDefault();
        $("#file-input").click();
      } else if (ctrl && e.key.toLowerCase() === "e") {
        e.preventDefault();
        if (liveRunning()) stopLive();
        else openLiveDialog();
      } else if (ctrl && e.key.toLowerCase() === "s") {
        e.preventDefault();
        save();
      } else if (ctrl && e.key.toLowerCase() === "b") {
        e.preventDefault();
        toggleSidebar();
      } else if (typing) {
        if (e.key === "Escape") e.target.blur();
      } else if (e.key === "/") {
        e.preventDefault();
        $("#filter-input").focus();
      } else if (["1", "2", "3"].includes(e.key) && !ctrl && !e.altKey) {
        switchView(["flows", "packets", "stats"][Number(e.key) - 1]);
      } else if (e.key === "ArrowDown" || e.key === "ArrowUp") {
        e.preventDefault();
        const d = e.key === "ArrowDown" ? 1 : -1;
        if (state.view === "packets") pkMove(d);
        else if (state.view === "flows") moveSelection(d);
      } else if (e.key === "ContextMenu" || (e.shiftKey && e.key === "F10")) {
        e.preventDefault();
        if (state.view === "flows") {
          const r = selectedRow();
          const tr = r && $(`#flows-body tr[data-idx="${r.idx}"]`);
          if (tr) {
            const b = tr.getBoundingClientRect();
            openMenu(b.left + 40, b.bottom, flowMenu(r));
          }
        } else if (state.view === "packets") {
          const pk = state.pk;
          const row = pk.pages.get(Math.floor(pk.selPos / PAGE))?.[pk.selPos % PAGE];
          const el = $(`#vlist-sizer [data-pos="${pk.selPos}"]`);
          if (row && el) {
            const b = el.getBoundingClientRect();
            openMenu(b.left + 40, b.bottom, packetMenu(row));
          }
        }
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

  function restorePrefs() {
    const theme = pref("theme");
    if (theme === "light" || theme === "dark") document.documentElement.dataset.theme = theme;
    state.mode = pref("mode") === "experto" ? "experto" : "simple";
    for (const b of $$(".segmented[aria-label='Nivel de detalle'] button")) b.setAttribute("aria-pressed", String(b.dataset.mode === state.mode));
    state.showNoise = pref("noise") === "1";
    $("#noise-toggle").checked = state.showNoise;
    state.combine = pref("combine") === "1";
    state.measure = pref("measure") === "bytes" ? "bytes" : "packets";
    try {
      const hist = JSON.parse(pref("history") || "[]");
      if (Array.isArray(hist)) state.history = hist.filter((x) => typeof x === "string").slice(0, 15);
    } catch {
      state.history = [];
    }
    renderHistory();
    if (pref("side") === "0") toggleSidebar(false);
    const view = pref("view");
    state.view = ["flows", "packets", "stats"].includes(view) ? view : "flows";
    for (const b of $$(".views [role=tab]")) b.setAttribute("aria-selected", String(b.dataset.view === state.view));
    $("#view-flows").hidden = state.view !== "flows";
    $("#view-packets").hidden = state.view !== "packets";
    $("#view-stats").hidden = state.view !== "stats";
  }

  async function start() {
    restorePrefs();
    bind();
    initSplitters();
    buildHelp();
    renderStatus();
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
