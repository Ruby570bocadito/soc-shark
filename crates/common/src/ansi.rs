//! Colores ANSI semánticos para la salida de terminal.
//!
//! Paleta SOC (`docs/09-ui-tui-gui.md`):
//! Rojo = alerta/crítico · Amarillo/ámbar = anomalía media · Cian = info ·
//! Gris = ruido de fondo. Respeta `NO_COLOR` y `TERM=dumb`.

/// Estado de la paleta; `enabled=false` produce texto sin códigos de escape.
#[derive(Debug, Clone, Copy)]
pub struct Palette {
    pub enabled: bool,
}

impl Palette {
    /// Activa/desactiva explícitamente.
    pub fn new(enabled: bool) -> Self {
        Palette { enabled }
    }

    /// Detecta automáticamente: desactivada si `--no-color`, `NO_COLOR` en
    /// entorno o terminal "dumb".
    pub fn auto(no_color_flag: bool) -> Self {
        let env_no = std::env::var_os("NO_COLOR").is_some()
            || std::env::var("TERM").map(|t| t == "dumb").unwrap_or(false)
            || !std::io::IsTerminal::is_terminal(&std::io::stdout());
        Palette {
            enabled: !no_color_flag && !env_no,
        }
    }

    fn wrap(&self, code: &str, s: &str) -> String {
        if self.enabled && !s.is_empty() {
            format!("\x1b[{code}m{s}\x1b[0m")
        } else {
            s.to_string()
        }
    }

    pub fn bold(&self, s: &str) -> String {
        self.wrap("1", s)
    }
    pub fn red(&self, s: &str) -> String {
        self.wrap("31", s)
    }
    pub fn green(&self, s: &str) -> String {
        self.wrap("32", s)
    }
    pub fn yellow(&self, s: &str) -> String {
        self.wrap("33", s)
    }
    pub fn cyan(&self, s: &str) -> String {
        self.wrap("36", s)
    }
    pub fn magenta(&self, s: &str) -> String {
        self.wrap("35", s)
    }
    pub fn gray(&self, s: &str) -> String {
        self.wrap("90", s)
    }
    pub fn white_bold(&self, s: &str) -> String {
        self.wrap("1;97", s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn con_y_sin_color() {
        let p = Palette::new(true);
        assert_eq!(p.red("x"), "\x1b[31mx\x1b[0m");
        assert_eq!(p.red(""), "");
        let off = Palette::new(false);
        assert_eq!(off.red("x"), "x");
    }
}
