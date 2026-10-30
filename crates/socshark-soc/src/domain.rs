//! Aproximación offline del dominio registrable (eTLD+1).
//!
//! Sin la Public Suffix List completa (≈ 10 000 entradas) se cubre el caso
//! que importa para un SOC: los sufijos de segundo nivel bajo un ccTLD
//! (`co.uk`, `com.au`, `com.br`, `co.jp`, `com.mx`, `org.uk`...). Así
//! `x.evil.co.uk` se reduce a `evil.co.uk` y no a `co.uk`.
//!
//! Lo usan la regla de túnel DNS (entropía solo sobre la parte a la
//! izquierda del dominio registrable) y la recomendación "bloquea el
//! dominio" de [`crate::explain`].

/// Etiquetas de segundo nivel genéricas bajo un ccTLD de dos letras que
/// actúan como sufijo público (`co.uk`, `com.br`, `ne.jp`, `gob.mx`...).
const SLD_GENERICOS: &[&str] = &[
    "ac", "co", "com", "edu", "gob", "go", "gov", "ltd", "me", "mil", "ne", "net", "nic", "nom",
    "or", "org", "plc", "sch",
];

/// Sufijo público de un nombre ya troceado: número de etiquetas finales que
/// forman el sufijo (1 = TLD simple, 2 = `co.uk` y similares).
fn suffix_len(labels: &[&str]) -> usize {
    if labels.len() >= 3 {
        let tld = labels[labels.len() - 1];
        let sld = labels[labels.len() - 2];
        let cc_tld = tld.len() == 2 && tld.bytes().all(|b| b.is_ascii_alphabetic());
        if cc_tld && SLD_GENERICOS.iter().any(|s| s.eq_ignore_ascii_case(sld)) {
            return 2;
        }
    }
    1
}

/// Dominio registrable aproximado (eTLD+1): `a.b.evil.co.uk` → `evil.co.uk`,
/// `x.y.example.com` → `example.com`. Nombres de una o dos etiquetas se
/// devuelven tal cual (sin el punto final).
pub fn registrable_domain(name: &str) -> &str {
    let name = name.trim_end_matches('.');
    let labels: Vec<&str> = name.split('.').collect();
    let keep = suffix_len(&labels) + 1;
    if labels.len() <= keep {
        return name;
    }
    // Longitud del prefijo a descartar: etiquetas + sus puntos.
    let skip: usize = labels[..labels.len() - keep]
        .iter()
        .map(|l| l.len() + 1)
        .sum();
    &name[skip..]
}

/// Etiquetas a la izquierda del dominio registrable (el "subdominio"), en
/// orden. `a.b.evil.com` → `["a", "b"]`; `evil.com` → `[]`.
pub fn subdomain_labels(name: &str) -> Vec<&str> {
    let name = name.trim_end_matches('.');
    let base = registrable_domain(name);
    if base.len() >= name.len() {
        return Vec::new();
    }
    name[..name.len() - base.len() - 1]
        .split('.')
        .filter(|l| !l.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registrable_con_sufijos_de_dos_niveles() {
        assert_eq!(registrable_domain("x.evil.co.uk"), "evil.co.uk");
        assert_eq!(registrable_domain("a.b.tienda.com.br."), "tienda.com.br");
        assert_eq!(registrable_domain("www.example.co.jp"), "example.co.jp");
        assert_eq!(registrable_domain("api.banco.com.mx"), "banco.com.mx");
        assert_eq!(registrable_domain("x.y.example.com"), "example.com");
        assert_eq!(registrable_domain("evil.example"), "evil.example");
        assert_eq!(registrable_domain("localhost"), "localhost");
        assert_eq!(registrable_domain("bbc.co.uk"), "bbc.co.uk");
        // ccTLD con SLD no genérico: dos etiquetas.
        assert_eq!(registrable_domain("www.google.de"), "google.de");
    }

    #[test]
    fn subdominio_separa_las_etiquetas_de_la_izquierda() {
        assert_eq!(
            subdomain_labels("settings-win.data.microsoft.com"),
            vec!["settings-win", "data"]
        );
        assert_eq!(subdomain_labels("x.evil.co.uk"), vec!["x"]);
        assert!(subdomain_labels("evil.com").is_empty());
        assert!(subdomain_labels("evil.co.uk").is_empty());
        assert!(subdomain_labels("").is_empty());
    }
}
