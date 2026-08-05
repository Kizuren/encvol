/// Remove sensitive key-value values before output. This is deliberately
/// conservative: false-positive redaction is safer than leaking recovery data.
pub fn redact(input: &str) -> String {
    input
        .lines()
        .map(|line| {
            let lower = line.to_ascii_lowercase();
            let sensitive = [
                "passphrase",
                "password",
                "secret",
                "token",
                "private_key",
                "luks_key",
            ]
            .iter()
            .any(|needle| lower.contains(needle));
            if sensitive {
                if let Some((key, _)) = line.split_once('=') {
                    return format!("{key}=<redacted>");
                }
                return "<redacted sensitive value>".into();
            }
            line.to_owned()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn secrets_are_hidden() {
        assert_eq!(
            redact("tang_token=abc\nmode=dhcp"),
            "tang_token=<redacted>\nmode=dhcp"
        );
    }
}
