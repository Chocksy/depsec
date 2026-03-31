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

/// Detect the git remote origin URL and return a clean display string.
/// e.g., `git@github.com:Chocksy/depsec.git` → `github.com/Chocksy/depsec`
pub fn detect_repo_url(root: &std::path::Path) -> Option<String> {
    let config_path = root.join(".git/config");
    let content = std::fs::read_to_string(config_path).ok()?;

    // Find [remote "origin"] section and extract url
    let mut in_origin = false;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed == "[remote \"origin\"]" {
            in_origin = true;
            continue;
        }
        if trimmed.starts_with('[') {
            in_origin = false;
            continue;
        }
        if in_origin {
            if let Some(url) = trimmed.strip_prefix("url = ") {
                return Some(clean_git_url(url));
            }
        }
    }
    None
}

fn clean_git_url(url: &str) -> String {
    let url = url.trim();

    // SSH: git@github.com:user/repo.git → github.com/user/repo
    if let Some(rest) = url.strip_prefix("git@") {
        return rest
            .replacen(':', "/", 1)
            .trim_end_matches(".git")
            .to_string();
    }

    // HTTPS: https://github.com/user/repo.git → github.com/user/repo
    let url = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url);

    url.trim_end_matches(".git").to_string()
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

    #[test]
    fn test_clean_git_url_ssh() {
        assert_eq!(
            clean_git_url("git@github.com:Chocksy/depsec.git"),
            "github.com/Chocksy/depsec"
        );
    }

    #[test]
    fn test_clean_git_url_https() {
        assert_eq!(
            clean_git_url("https://github.com/Chocksy/depsec.git"),
            "github.com/Chocksy/depsec"
        );
    }

    #[test]
    fn test_clean_git_url_no_suffix() {
        assert_eq!(
            clean_git_url("https://github.com/user/repo"),
            "github.com/user/repo"
        );
    }

    #[test]
    fn test_detect_repo_url_current_project() {
        // Running from the depsec repo itself
        let url = detect_repo_url(std::path::Path::new("."));
        assert!(url.is_some());
        assert!(url.unwrap().contains("depsec"));
    }
}
