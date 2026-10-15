//! TUI (Fase 2): explorador Flow-First sobre una captura analizada.
//!
//! Modo offline: la TUI consume la misma lista de [`EnrichedFlow`] que la
//! CLI (tabla/JSONL); cuando exista el daemon de captura en vivo se
//! enchufará a su JSONL sin cambiar el modelo. El estado ([`TuiApp`]) y sus
//! reglas están testeados sin terminal; solo el renderizado depende de
//! ratatui (feature `tui`, activada por defecto).
//!
//! Atajos: `j/k` o flechas mueven, `Enter` expande el flujo, `/` abre la
//! línea de filtro (DSL completo), `Enter` aplica, `Esc` cancela, `q` sale.

use socshark_core::EnrichedFlow;
use socshark_filter::{eval, parse};

/// Teclas lógicas desacopladas del backend de terminal (testeable sin TTY).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Key {
    Up,
    Down,
    Enter,
    Esc,
    Backspace,
    Char(char),
    Other,
}

/// Modo de la interfaz: navegación normal o edición del filtro.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Normal,
    Filter,
}

/// Estado de la TUI: lista filtrada, selección, expansión y línea de filtro.
pub struct TuiApp {
    all: Vec<EnrichedFlow>,
    /// Índices sobre `all` visibles tras el filtro activo.
    view: Vec<usize>,
    selected: usize,
    expanded: bool,
    mode: Mode,
    input: String,
    expr: Option<String>,
    error: Option<String>,
    quit: bool,
}

impl TuiApp {
    pub fn new(flows: Vec<EnrichedFlow>) -> Self {
        let mut app = Self {
            all: flows,
            view: Vec::new(),
            selected: 0,
            expanded: false,
            mode: Mode::Normal,
            input: String::new(),
            expr: None,
            error: None,
            quit: false,
        };
        app.refresh();
        app
    }

    pub fn should_quit(&self) -> bool {
        self.quit
    }
    pub fn total(&self) -> usize {
        self.all.len()
    }
    pub fn view_len(&self) -> usize {
        self.view.len()
    }
    pub fn selected(&self) -> usize {
        self.selected
    }
    pub fn is_expanded(&self) -> bool {
        self.expanded
    }
    pub fn mode(&self) -> Mode {
        self.mode
    }
    pub fn input(&self) -> &str {
        &self.input
    }
    pub fn expr(&self) -> Option<&str> {
        self.expr.as_deref()
    }
    pub fn error(&self) -> Option<&str> {
        self.error.as_deref()
    }
    pub fn visible(&self, i: usize) -> Option<&EnrichedFlow> {
        self.view.get(i).map(|&idx| &self.all[idx])
    }

    /// Recalcula la vista aplicando el DSL. Un filtro inválido deja la vista
    /// anterior y muestra el error en la línea de estado.
    fn refresh(&mut self) {
        self.error = None;
        self.view = match &self.expr {
            None => (0..self.all.len()).collect(),
            Some(src) => match parse(src) {
                Ok(e) => self
                    .all
                    .iter()
                    .enumerate()
                    .filter(|(_, f)| eval(&e, f))
                    .map(|(i, _)| i)
                    .collect(),
                Err(err) => {
                    self.error = Some(err.to_string());
                    (0..self.all.len()).collect()
                }
            },
        };
        if self.selected >= self.view.len() {
            self.selected = self.view.len().saturating_sub(1);
        }
    }

    /// Procesa una tecla lógica según el modo actual.
    pub fn on_key(&mut self, k: Key) {
        match self.mode {
            Mode::Normal => match k {
                Key::Char('q') => self.quit = true,
                Key::Down | Key::Char('j') => self.move_down(1),
                Key::Up | Key::Char('k') => self.move_up(1),
                Key::Char('g') => self.selected = 0,
                Key::Char('G') => self.move_down(self.view.len()),
                Key::Enter => {
                    if self.selected < self.view.len() {
                        self.expanded = !self.expanded;
                    }
                }
                Key::Char('/') => {
                    self.mode = Mode::Filter;
                    self.input.clear();
                    self.error = None;
                }
                _ => {}
            },
            Mode::Filter => match k {
                Key::Enter => {
                    let src = self.input.trim().to_string();
                    self.expr = if src.is_empty() { None } else { Some(src) };
                    self.mode = Mode::Normal;
                    self.expanded = false;
                    self.refresh();
                }
                Key::Esc => self.mode = Mode::Normal,
                Key::Backspace => {
                    self.input.pop();
                }
                Key::Char(c) => self.input.push(c),
                Key::Other => {}
                _ => {}
            },
        }
    }

    pub fn move_down(&mut self, n: usize) {
        if self.view.is_empty() {
            return;
        }
        self.selected = (self.selected + n).min(self.view.len() - 1);
    }

    pub fn move_up(&mut self, n: usize) {
        self.selected = self.selected.saturating_sub(n);
    }

    /// Líneas de detalle del flujo seleccionado (panel inferior al expandir).
    pub fn detail_lines(&self) -> Vec<String> {
        let Some(f) = self.visible(self.selected) else {
            return vec!["(sin selección)".into()];
        };
        let mut v = vec![
            format!("flujo    : {}", f.flow_id),
            format!(
                "tiempo   : {} µs de duración · primer paquete {}",
                f.duration_micros, f.first_seen_micros
            ),
            format!(
                "volumen  : {} paq / {} B (ida) · {} paq / {} B (vuelta)",
                f.packets, f.bytes, f.packets_rev, f.bytes_rev
            ),
            format!(
                "protocolo: {} · estado {} · IP v{}",
                f.l7_protocol.as_str(),
                f.state.as_str(),
                f.ip_version
            ),
        ];
        if let Some(d) = f.resolved_domain.as_deref() {
            v.push(format!("dominio  : {d}"));
        }
        if let Some(dns) = f.dns.as_ref() {
            for q in &dns.queries {
                v.push(format!(
                    "dns      : {} ({}), rcode {}",
                    q.name,
                    socshark_core::dns_type_str(q.qtype),
                    dns.rcode
                        .map(|r| socshark_core::dns_rcode_str(r).to_string())
                        .unwrap_or_else(|| "sin respuesta".into())
                ));
            }
            for a in &dns.answers {
                let val = a
                    .address
                    .as_ref()
                    .map(|ip| ip.to_string())
                    .or_else(|| a.target.clone())
                    .unwrap_or_default();
                v.push(format!(
                    "respuesta: {} {} → {} (ttl {})",
                    a.name,
                    socshark_core::dns_type_str(a.rtype),
                    val,
                    a.ttl
                ));
            }
        }
        if f.is_background_noise {
            v.push("ruido    : sí (tráfico de fondo atenuado)".into());
        }
        if !f.human_summary.is_empty() {
            v.push(format!("resumen  : {}", f.human_summary));
        }
        for a in &f.alerts {
            v.push(format!(
                "alerta   : ({}) {} · {}{}",
                a.severity.as_str(),
                a.id,
                a.detail,
                a.mitre
                    .as_ref()
                    .map(|m| format!(" · MITRE {m}"))
                    .unwrap_or_default()
            ));
        }
        if f.process_name.is_some() || f.pid.is_some() {
            v.push(format!(
                "proceso  : {} (pid {:?})",
                f.process_name.as_deref().unwrap_or("?"),
                f.pid
            ));
        }
        v
    }

    /// Entradas del panel de alertas: `(flujo, línea)`.
    pub fn alert_lines(&self) -> Vec<(String, String)> {
        let mut out = Vec::new();
        for i in 0..self.view.len() {
            if let Some(f) = self.visible(i) {
                for a in &f.alerts {
                    out.push((
                        f.flow_id.0.clone(),
                        format!("({}) {} · {}", a.severity.as_str(), a.id, a.detail),
                    ));
                }
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use socshark_core::{FlowId, FlowState, L7Protocol, Transport};
    use std::net::{IpAddr, Ipv4Addr};

    fn flow(id: &str, risk: u8, noise: bool, domain: Option<&str>) -> EnrichedFlow {
        EnrichedFlow {
            flow_id: FlowId(id.into()),
            state: FlowState::Idle,
            transport: Transport::Tcp,
            l7_protocol: L7Protocol::Tls,
            ip_version: 4,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            src_port: 52000,
            dst_ip: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            dst_port: 443,
            src_mac: None,
            dst_mac: None,
            first_seen_micros: 1,
            last_seen_micros: 2,
            duration_micros: 1,
            packets: 1,
            bytes: 10,
            packets_rev: 1,
            bytes_rev: 20,
            tcp_flags: Default::default(),
            process_name: None,
            pid: None,
            user: None,
            resolved_domain: domain.map(|d| d.into()),
            dns: None,
            dst_geo_asn: None,
            ja4_fingerprint: None,
            is_background_noise: noise,
            human_summary: String::new(),
            risk_score: risk,
            alerts: Vec::new(),
            extracted_files: Vec::new(),
        }
    }

    fn app() -> TuiApp {
        TuiApp::new(vec![
            flow("tcp/a-1", 0, false, Some("a.example")),
            flow("tcp/b-2", 60, false, None),
            flow("udp/c-3", 0, true, None),
        ])
    }

    #[test]
    fn navegacion_con_limites() {
        let mut a = app();
        assert_eq!(a.selected(), 0);
        a.on_key(Key::Down);
        a.on_key(Key::Char('j'));
        assert_eq!(a.selected(), 2);
        a.on_key(Key::Down); // no pasa del último
        assert_eq!(a.selected(), 2);
        a.on_key(Key::Char('k'));
        assert_eq!(a.selected(), 1);
        a.on_key(Key::Char('G'));
        assert_eq!(a.selected(), 2);
        a.on_key(Key::Char('g'));
        assert_eq!(a.selected(), 0);
    }

    #[test]
    fn filtro_dsl_narra_la_vista() {
        let mut a = app();
        a.on_key(Key::Char('/'));
        assert_eq!(a.mode(), Mode::Filter);
        for c in "flow.risk >= 30".chars() {
            a.on_key(Key::Char(c));
        }
        a.on_key(Key::Enter);
        assert_eq!(a.mode(), Mode::Normal);
        assert_eq!(a.view_len(), 1);
        assert!(a.error().is_none());
        // El filtro sigue activo y visible.
        assert_eq!(a.expr(), Some("flow.risk >= 30"));
    }

    #[test]
    fn filtro_invalido_muestra_error_y_conserva_vista() {
        let mut a = app();
        a.on_key(Key::Char('/'));
        for c in "ip.version == seis".chars() {
            a.on_key(Key::Char(c));
        }
        a.on_key(Key::Enter);
        // "seis" es un bareword válido pero no numérico: sin resultados, sin panic.
        assert_eq!(a.view_len(), 0);
        // Filtro roto: error visible y vista completa de respaldo.
        a.on_key(Key::Char('/'));
        a.on_key(Key::Backspace);
        for c in "flow.risk >=".chars() {
            a.on_key(Key::Char(c));
        }
        a.on_key(Key::Enter);
        assert!(
            a.error().is_some(),
            "parser debe fallar con expresión incompleta"
        );
        assert_eq!(a.view_len(), 3, "vista anterior conservada");
    }

    #[test]
    fn expandir_y_detalle() {
        let mut a = app();
        assert!(!a.is_expanded());
        a.on_key(Key::Enter);
        assert!(a.is_expanded());
        let lines = a.detail_lines();
        assert!(lines.iter().any(|l| l.contains("a.example")));
        assert!(lines.iter().any(|l| l.contains("IP v4")));
        a.on_key(Key::Enter);
        assert!(!a.is_expanded());
    }

    #[test]
    fn escapar_cancela_filtro_y_q_sale() {
        let mut a = app();
        a.on_key(Key::Char('/'));
        a.on_key(Key::Esc);
        assert_eq!(a.mode(), Mode::Normal);
        assert_eq!(a.input(), "");
        a.on_key(Key::Char('q'));
        assert!(a.should_quit());
    }
}

// ------------------------------------------------ renderizado (feature tui)

#[cfg(feature = "tui")]
pub mod term {
    //! Loop de terminal con ratatui + crossterm. Aislado en `term` para que
    //! el modelo ([`super::TuiApp`]) sea testeable sin un TTY.

    use super::{Key, TuiApp};
    use anyhow::Result;
    use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind};
    use crossterm::{
        execute,
        terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
    };
    use ratatui::backend::CrosstermBackend;
    use ratatui::prelude::*;
    use ratatui::widgets::*;
    use std::io;
    use std::path::Path;
    use std::time::Duration;

    /// Ejecuta la TUI sobre una captura ya analizada (incluye el ruido,
    /// atenuado en pantalla).
    pub fn run(read: &Path, initial_filter: Option<&str>) -> Result<()> {
        let cfg = socshark_core::config::PipelineConfig::default();
        let out = crate::pipeline::run_capture(read, initial_filter, true, &cfg)?;
        let mut app = TuiApp::new(out.flows);
        if let Some(src) = initial_filter {
            // Precarga la línea de filtro para que el analista la vea/editable.
            app.preset_filter(src);
        }

        let mut stdout = io::stdout();
        enable_raw_mode()?;
        execute!(stdout, EnterAlternateScreen)?;
        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend)?;

        let res = event_loop(&mut terminal, &mut app);

        disable_raw_mode()?;
        execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
        terminal.show_cursor()?;
        res
    }

    fn event_loop(
        terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
        app: &mut TuiApp,
    ) -> Result<()> {
        loop {
            terminal.draw(|f| draw(f, app))?;
            if event::poll(Duration::from_millis(250))? {
                if let Event::Key(key) = event::read()? {
                    if key.kind == KeyEventKind::Press {
                        app.on_key(map_key(key));
                        if app.should_quit() {
                            return Ok(());
                        }
                    }
                }
            }
        }
    }

    fn map_key(k: KeyEvent) -> Key {
        match k.code {
            KeyCode::Up => Key::Up,
            KeyCode::Down => Key::Down,
            KeyCode::Enter => Key::Enter,
            KeyCode::Esc => Key::Esc,
            KeyCode::Backspace => Key::Backspace,
            KeyCode::Char(c) => Key::Char(c),
            _ => Key::Other,
        }
    }

    fn truncate(s: &str, max: usize) -> String {
        if s.chars().count() <= max {
            s.to_string()
        } else {
            let t: String = s.chars().take(max - 1).collect();
            format!("{t}…")
        }
    }

    fn fmt_bytes(n: u64) -> String {
        if n >= 1024 * 1024 {
            format!("{:.1} MiB", n as f64 / (1024.0 * 1024.0))
        } else if n >= 1024 {
            format!("{:.1} KiB", n as f64 / 1024.0)
        } else {
            format!("{n} B")
        }
    }

    fn draw(f: &mut Frame, app: &TuiApp) {
        let header = Line::from(vec![
            Span::styled(" soc-shark ", Style::default().bold()),
            Span::raw(format!(
                "· {} / {} flujos · q salir · j/k mover · Enter expandir · / filtro",
                app.view_len(),
                app.total()
            )),
        ]);
        let [top, main, status] = Layout::vertical([
            Constraint::Length(1),
            Constraint::Min(0),
            Constraint::Length(1),
        ])
        .areas(f.area());
        f.render_widget(Paragraph::new(header), top);

        let [left, right] =
            Layout::horizontal([Constraint::Min(60), Constraint::Length(44)]).areas(main);

        // Lista de flujos (izquierda) + detalle si hay expansión.
        if app.is_expanded() {
            let [list_area, detail] =
                Layout::vertical([Constraint::Percentage(55), Constraint::Percentage(45)])
                    .areas(left);
            render_flows(f, app, list_area);
            let detail_lines: Vec<Line> = app.detail_lines().into_iter().map(Line::from).collect();
            f.render_widget(
                Paragraph::new(detail_lines)
                    .block(Block::bordered().title(" detalle del flujo "))
                    .wrap(Wrap { trim: false }),
                detail,
            );
        } else {
            render_flows(f, app, left);
        }

        // Panel de alertas (derecha).
        let alert_items: Vec<ListItem> = app
            .alert_lines()
            .into_iter()
            .map(|(flow_id, line)| {
                ListItem::new(vec![
                    Line::from(truncate(&line, 40)),
                    Line::from(Span::styled(
                        truncate(&flow_id, 40),
                        Style::default().fg(Color::DarkGray),
                    )),
                ])
            })
            .collect();
        let alerts = List::new(alert_items)
            .block(Block::bordered().title(format!(" alertas SOC · {} ", app.alert_lines().len())))
            .highlight_style(Style::default().bg(Color::Blue));
        f.render_widget(alerts, right);

        // Línea de estado / filtro.
        let status_line = match app.mode() {
            super::Mode::Filter => Line::from(vec![
                Span::styled(" filtro ▏ ", Style::default().bold()),
                Span::raw(app.input().to_string()),
            ]),
            super::Mode::Normal => match (app.expr(), app.error()) {
                (_, Some(err)) => Line::from(Span::styled(
                    format!(" error de filtro: {err} "),
                    Style::default().fg(Color::Red).bold(),
                )),
                (Some(e), None) => Line::from(format!(" filtro activo: {e} · / editar")),
                (None, None) => Line::from(Span::styled(
                    " listo · / para filtrar con el DSL",
                    Style::default().fg(Color::DarkGray),
                )),
            },
        };
        f.render_widget(Paragraph::new(status_line), status);
    }

    fn render_flows(f: &mut Frame, app: &TuiApp, area: Rect) {
        let items: Vec<ListItem> = (0..app.view_len())
            .map(|i| {
                let flow = app.visible(i).expect("índice válido");
                let alerts = if flow.alerts.is_empty() {
                    "-".to_string()
                } else {
                    flow.alerts
                        .iter()
                        .map(|a| a.id.as_str())
                        .collect::<Vec<_>>()
                        .join(",")
                };
                let line = format!(
                    "{:<46} {:4} {:>5} {:>9} {:>4} {}",
                    truncate(&flow.flow_id.0, 46),
                    flow.l7_protocol.as_str(),
                    flow.packets + flow.packets_rev,
                    fmt_bytes(flow.bytes + flow.bytes_rev),
                    flow.risk_score,
                    alerts,
                );
                let mut spans = vec![Span::raw(line)];
                if flow.is_background_noise {
                    spans = vec![Span::styled(
                        spans[0].content.clone(),
                        Style::default().fg(Color::DarkGray),
                    )];
                } else if flow.risk_score >= 50 {
                    spans[0].style = Style::default().fg(Color::Red).bold();
                } else if flow.risk_score > 0 {
                    spans[0].style = Style::default().fg(Color::Yellow);
                }
                ListItem::new(Line::from(spans))
            })
            .collect();

        let list = List::new(items)
            .block(Block::bordered().title(" flujos (Flow-First) "))
            .highlight_style(Style::default().bg(Color::Blue).fg(Color::White))
            .highlight_symbol("▸ ");
        let mut state = ListState::default();
        if app.view_len() > 0 {
            state.select(Some(app.selected()));
        }
        f.render_stateful_widget(list, area, &mut state);
    }
}

#[cfg(feature = "tui")]
impl TuiApp {
    /// Precarga una expresión de filtro (sin reevaluar: ya la aplicó la CLI).
    pub(crate) fn preset_filter(&mut self, src: &str) {
        self.expr = Some(src.to_string());
        self.refresh();
    }
}

#[cfg(feature = "tui")]
pub use term::run;
