//! Idioma de los textos para personas (ADR-015).
//!
//! El español es el idioma de referencia: el JSONL, ECS, Wazuh, los `id`
//! de alerta y el `human_summary` que se exporta van siempre en español
//! (contrato estable). El inglés es una segunda vista que eligen la GUI y
//! su informe; las funciones `*_in` reciben el [`Lang`] y las de siempre
//! equivalen a `Lang::Es`.

/// Idioma de un texto para personas.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Lang {
    /// Español (el de referencia).
    #[default]
    Es,
    /// Inglés.
    En,
}

impl Lang {
    /// Desde un código de idioma (`en`, `en-US`, `es`…): inglés si empieza
    /// por `en`; cualquier otra cosa, español.
    pub fn from_code(code: &str) -> Self {
        let c = code.trim();
        if c.len() >= 2 && c[..2].eq_ignore_ascii_case("en") {
            Lang::En
        } else {
            Lang::Es
        }
    }

    /// Código ISO 639-1 (`es`, `en`), para `<html lang>`.
    pub fn code(self) -> &'static str {
        match self {
            Lang::Es => "es",
            Lang::En => "en",
        }
    }

    /// El valor que toca en este idioma.
    pub fn pick<T>(self, es: T, en: T) -> T {
        match self {
            Lang::Es => es,
            Lang::En => en,
        }
    }
}

/// `format!` con una plantilla por idioma y los mismos argumentos:
/// `tr!(lang, "el equipo {ip}", "the device {ip}")`. Las variables
/// capturadas por nombre funcionan como en `format!`.
#[macro_export]
macro_rules! tr {
    ($lang:expr, $es:literal, $en:literal $(, $arg:expr)* $(,)?) => {
        match $lang {
            $crate::Lang::Es => format!($es $(, $arg)*),
            $crate::Lang::En => format!($en $(, $arg)*),
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codigos_de_idioma() {
        assert_eq!(Lang::from_code("en"), Lang::En);
        assert_eq!(Lang::from_code("en-GB"), Lang::En);
        assert_eq!(Lang::from_code("EN"), Lang::En);
        assert_eq!(Lang::from_code("es-ES"), Lang::Es);
        assert_eq!(Lang::from_code(""), Lang::Es);
        assert_eq!(Lang::from_code("e"), Lang::Es);
        assert_eq!(Lang::from_code("fr"), Lang::Es);
        assert_eq!(Lang::En.pick("hola", "hello"), "hello");
        let ip = "1.2.3.4";
        assert_eq!(
            tr!(Lang::En, "el equipo {ip}", "the device {ip}"),
            "the device 1.2.3.4"
        );
        assert_eq!(tr!(Lang::Es, "{} y {}", "{} and {}", 1, 2), "1 y 2");
    }
}
