// Shared utility functions used across depsec modules.

/// Shannon entropy of a string (bits per character).
/// Used by pattern detection (P007) and secret detection (S021-S023).
pub fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut freq = [0u32; 256];
    for &b in s.as_bytes() {
        freq[b as usize] += 1;
    }
    let len = s.len() as f64;
    freq.iter()
        .filter(|&&count| count > 0)
        .map(|&count| {
            let p = count as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// Capitalize the first character of a string.
/// Used by output rendering and scorecard generation.
pub fn capitalize(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        None => String::new(),
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shannon_entropy_empty() {
        assert_eq!(shannon_entropy(""), 0.0);
    }

    #[test]
    fn test_shannon_entropy_uniform() {
        assert_eq!(shannon_entropy("aaaa"), 0.0);
    }

    #[test]
    fn test_shannon_entropy_mixed() {
        let entropy = shannon_entropy("abcdefghijklmnopqrstuvwxyz");
        assert!(entropy > 4.0);
    }

    #[test]
    fn test_shannon_entropy_high() {
        let entropy = shannon_entropy("aK3fR9xL2mN5pQ8sT1vW4yB7");
        assert!(entropy > 3.5);
    }

    #[test]
    fn test_capitalize() {
        assert_eq!(capitalize("workflows"), "Workflows");
        assert_eq!(capitalize("deps"), "Deps");
        assert_eq!(capitalize(""), "");
        assert_eq!(capitalize("a"), "A");
    }
}
