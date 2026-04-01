use std::path::{Path, PathBuf};

use anyhow::Result;
use sha2::{Digest, Sha256};

/// Generate randomized canary token files that look like real credentials.
/// Place them in the target directory (sandbox root or temp dir).
/// Returns the paths of generated canary files for monitoring.
pub fn generate_canary_tokens(target_home: &Path) -> Result<Vec<CanaryToken>> {
    let mut tokens = Vec::new();

    // Randomize which subset of canaries we place (attacker can't predict)
    let seed = random_seed();

    // Helper: write file and record content hash for tamper detection
    let mut place = |path: PathBuf, kind: &str, content: &str| -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&path, content)?;
        let content_hash = hash_content(content.as_bytes());
        tokens.push(CanaryToken {
            path,
            kind: kind.into(),
            content_hash,
        });
        Ok(())
    };

    // Always place SSH key — most commonly targeted
    let ssh_dir = target_home.join(".ssh");
    std::fs::create_dir_all(&ssh_dir)?;
    let ssh_key = generate_fake_ssh_key(&seed);
    std::fs::write(ssh_dir.join("id_rsa.pub"), generate_fake_ssh_pubkey(&seed))?;
    place(ssh_dir.join("id_rsa"), "SSH Private Key", &ssh_key)?;

    // AWS credentials
    let aws_creds = generate_fake_aws_credentials(&seed);
    place(
        target_home.join(".aws/credentials"),
        "AWS Credentials",
        &aws_creds,
    )?;

    // .env file with random API keys
    let env_content = generate_fake_env(&seed);
    place(target_home.join(".env"), "Environment File", &env_content)?;

    // .npmrc with fake token (conditionally — randomize)
    if !seed.is_multiple_of(3) {
        let npmrc = generate_fake_npmrc(&seed);
        place(target_home.join(".npmrc"), "npm Token", &npmrc)?;
    }

    // GitHub CLI token (conditionally)
    if seed.is_multiple_of(2) {
        let gh_hosts = generate_fake_gh_hosts(&seed);
        place(
            target_home.join(".config/gh/hosts.yml"),
            "GitHub CLI Token",
            &gh_hosts,
        )?;
    }

    Ok(tokens)
}

/// Generate a realistic-looking home directory with canary credential files
/// AND realistic dotfiles that make the sandbox look like a real developer machine.
pub fn generate_honeypot_home(target_home: &Path) -> Result<Vec<CanaryToken>> {
    // First, generate the canary credential tokens
    let tokens = generate_canary_tokens(target_home)?;

    // Then add realistic dotfiles that aren't canaries but make the home look real
    generate_realistic_dotfiles(target_home)?;

    Ok(tokens)
}

/// Create non-canary dotfiles that make a fake HOME look lived-in
fn generate_realistic_dotfiles(home: &Path) -> Result<()> {
    std::fs::write(
        home.join(".bashrc"),
        "# ~/.bashrc\nexport EDITOR=vim\nexport PATH=\"$HOME/.local/bin:$PATH\"\n\
         alias ll='ls -la'\nalias gs='git status'\n",
    )?;

    std::fs::write(
        home.join(".profile"),
        "# ~/.profile\n[ -f ~/.bashrc ] && . ~/.bashrc\n",
    )?;

    let seed = random_seed();
    let name = match seed % 5 {
        0 => "Alex Chen",
        1 => "Jordan Smith",
        2 => "Sam Rodriguez",
        3 => "Taylor Kim",
        _ => "Morgan Lee",
    };
    std::fs::write(
        home.join(".gitconfig"),
        format!(
            "[user]\n\tname = {name}\n\temail = {}@company.com\n[core]\n\teditor = vim\n[pull]\n\trebase = true\n",
            name.split(' ').next().unwrap_or("dev").to_lowercase(),
        ),
    )?;

    std::fs::write(
        home.join(".node_repl_history"),
        "console.log('hello')\nprocess.env\nrequire('fs').readdirSync('.')\n",
    )?;

    let npm_dir = home.join(".npm");
    std::fs::create_dir_all(&npm_dir)?;
    std::fs::write(
        npm_dir.join(".npmrc"),
        "registry=https://registry.npmjs.org/\n",
    )?;

    std::fs::create_dir_all(home.join(".config"))?;

    Ok(())
}

#[derive(Debug, Clone)]
pub struct CanaryToken {
    pub path: PathBuf,
    pub kind: String,
    /// SHA-256 hash of the original content — used for tamper detection
    pub content_hash: String,
}

/// Clean up canary tokens after sandbox run
pub fn cleanup_canary_tokens(tokens: &[CanaryToken]) {
    for token in tokens {
        let _ = std::fs::remove_file(&token.path);
    }
}

// ── Generators ──────────────────────────────────────────────────────

fn generate_fake_ssh_key(seed: &u64) -> String {
    let random_bytes = pseudo_random_string(*seed, 1680);
    format!(
        "-----BEGIN OPENSSH PRIVATE KEY-----\n{}\n-----END OPENSSH PRIVATE KEY-----\n",
        base64_lines(&random_bytes, 70)
    )
}

fn generate_fake_ssh_pubkey(seed: &u64) -> String {
    let random_bytes = pseudo_random_string(*seed + 1, 372);
    format!(
        "ssh-rsa {} canary@depsec-sandbox\n",
        random_bytes.chars().take(372).collect::<String>()
    )
}

fn generate_fake_aws_credentials(seed: &u64) -> String {
    let access_key = format!(
        "AKIA{}",
        pseudo_random_alphanum(*seed + 2, 16).to_uppercase()
    );
    let secret_key = pseudo_random_base64(*seed + 3, 40);
    format!(
        "[default]\naws_access_key_id = {access_key}\naws_secret_access_key = {secret_key}\nregion = us-east-1\n"
    )
}

fn generate_fake_env(seed: &u64) -> String {
    let db_pass = pseudo_random_alphanum(*seed + 4, 24);
    let api_key = pseudo_random_alphanum(*seed + 5, 32);
    let jwt_secret = pseudo_random_base64(*seed + 6, 48);
    format!(
        "DATABASE_URL=postgres://admin:{db_pass}@db.example.com:5432/app\nAPI_KEY={api_key}\nJWT_SECRET={jwt_secret}\nSECRET_KEY_BASE={}\n",
        pseudo_random_alphanum(*seed + 7, 64)
    )
}

fn generate_fake_npmrc(seed: &u64) -> String {
    let token = pseudo_random_alphanum(*seed + 8, 36);
    format!("//registry.npmjs.org/:_authToken=npm_{token}\nalways-auth=true\n")
}

fn generate_fake_gh_hosts(seed: &u64) -> String {
    let token = pseudo_random_alphanum(*seed + 9, 36);
    format!(
        "github.com:\n    oauth_token: ghp_{token}\n    user: developer\n    git_protocol: https\n"
    )
}

/// SHA-256 hash of file content — used for reliable tamper detection
/// (timestamp-based detection is unreliable on macOS APFS)
fn hash_content(data: &[u8]) -> String {
    let hash = Sha256::digest(data);
    format!("{:x}", hash)
}

/// Check if a canary token was tampered with by comparing content hashes.
/// Returns the access type: "deleted", "tampered", or None if untouched.
pub fn check_canary_tamper(token: &CanaryToken) -> Option<String> {
    if !token.path.exists() {
        return Some("deleted".into());
    }
    match std::fs::read(&token.path) {
        Ok(content) => {
            let current_hash = hash_content(&content);
            if current_hash != token.content_hash {
                Some("tampered".into())
            } else {
                None
            }
        }
        Err(_) => Some("unreadable".into()),
    }
}

// ── Pseudo-random utilities (deterministic from seed for reproducibility) ──

fn random_seed() -> u64 {
    // Mix process ID + timestamp for unpredictable seed
    let pid = std::process::id() as u64;
    let time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;

    // Mix with SHA-256 for good distribution
    let mut hasher = Sha256::new();
    hasher.update(pid.to_le_bytes());
    hasher.update(time.to_le_bytes());
    let hash = hasher.finalize();
    u64::from_le_bytes(hash[..8].try_into().unwrap())
}

/// LCG-based pseudo-random string generator with configurable charset
fn pseudo_random_chars(seed: u64, len: usize, charset: &[u8]) -> String {
    let mut result = Vec::with_capacity(len);
    let mut state = seed;
    for _ in 0..len {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let idx = ((state >> 33) as usize) % charset.len();
        result.push(charset[idx]);
    }
    String::from_utf8(result).unwrap()
}

fn pseudo_random_string(seed: u64, len: usize) -> String {
    pseudo_random_chars(
        seed,
        len,
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
    )
}

fn pseudo_random_alphanum(seed: u64, len: usize) -> String {
    pseudo_random_chars(
        seed,
        len,
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
    )
}

fn pseudo_random_base64(seed: u64, len: usize) -> String {
    pseudo_random_chars(
        seed,
        len,
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
    )
}

fn base64_lines(data: &str, line_len: usize) -> String {
    data.as_bytes()
        .chunks(line_len)
        .map(|chunk| std::str::from_utf8(chunk).unwrap_or(""))
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_canary_tokens() {
        let dir = tempfile::TempDir::new().unwrap();
        let tokens = generate_canary_tokens(dir.path()).unwrap();

        // Should always generate at least SSH + AWS + .env
        assert!(tokens.len() >= 3);

        // SSH key should exist and look real
        let ssh_key = std::fs::read_to_string(dir.path().join(".ssh/id_rsa")).unwrap();
        assert!(ssh_key.contains("BEGIN OPENSSH PRIVATE KEY"));
        assert!(ssh_key.contains("END OPENSSH PRIVATE KEY"));

        // AWS credentials should look real
        let aws = std::fs::read_to_string(dir.path().join(".aws/credentials")).unwrap();
        assert!(aws.contains("AKIA")); // Fake AWS key prefix
        assert!(aws.contains("aws_secret_access_key"));

        // .env should have database URL
        let env = std::fs::read_to_string(dir.path().join(".env")).unwrap();
        assert!(env.contains("DATABASE_URL"));
        assert!(env.contains("API_KEY"));
    }

    #[test]
    fn test_canary_randomization() {
        let dir1 = tempfile::TempDir::new().unwrap();
        let dir2 = tempfile::TempDir::new().unwrap();

        generate_canary_tokens(dir1.path()).unwrap();
        generate_canary_tokens(dir2.path()).unwrap();

        // Keys should be different between runs
        let key1 = std::fs::read_to_string(dir1.path().join(".ssh/id_rsa")).unwrap();
        let key2 = std::fs::read_to_string(dir2.path().join(".ssh/id_rsa")).unwrap();
        assert_ne!(key1, key2, "Canary tokens should be randomized per run");
    }

    #[test]
    fn test_cleanup_canary_tokens() {
        let dir = tempfile::TempDir::new().unwrap();
        let tokens = generate_canary_tokens(dir.path()).unwrap();

        // All files should exist
        for token in &tokens {
            assert!(token.path.exists());
        }

        cleanup_canary_tokens(&tokens);

        // All files should be removed
        for token in &tokens {
            assert!(!token.path.exists());
        }
    }

    #[test]
    fn test_fake_aws_key_format() {
        let seed = 12345u64;
        let creds = generate_fake_aws_credentials(&seed);
        // Access key should start with AKIA and be 20 chars
        assert!(creds.contains("AKIA"));
        let key_line = creds
            .lines()
            .find(|l| l.contains("aws_access_key_id"))
            .unwrap();
        let key = key_line.split('=').nth(1).unwrap().trim();
        assert_eq!(key.len(), 20); // AKIA + 16 chars
        assert!(key.starts_with("AKIA"));
    }

    #[test]
    fn test_generate_honeypot_home() {
        let dir = tempfile::TempDir::new().unwrap();
        let tokens = generate_honeypot_home(dir.path()).unwrap();

        // Should have canary tokens
        assert!(tokens.len() >= 3);

        // Should also have realistic dotfiles
        assert!(dir.path().join(".bashrc").exists());
        assert!(dir.path().join(".gitconfig").exists());
        assert!(dir.path().join(".profile").exists());
        assert!(dir.path().join(".node_repl_history").exists());

        // .gitconfig should look realistic
        let gitconfig = std::fs::read_to_string(dir.path().join(".gitconfig")).unwrap();
        assert!(gitconfig.contains("[user]"));
        assert!(gitconfig.contains("@company.com"));
    }

    #[test]
    fn test_canary_tamper_detection_untouched() {
        let dir = tempfile::TempDir::new().unwrap();
        let tokens = generate_canary_tokens(dir.path()).unwrap();

        for token in &tokens {
            assert!(
                check_canary_tamper(token).is_none(),
                "Untouched canary {} should not be flagged as tampered",
                token.kind
            );
        }
    }

    #[test]
    fn test_canary_tamper_detection_modified() {
        let dir = tempfile::TempDir::new().unwrap();
        let tokens = generate_canary_tokens(dir.path()).unwrap();

        std::fs::write(&tokens[0].path, "STOLEN BY ATTACKER").unwrap();

        assert_eq!(
            check_canary_tamper(&tokens[0]),
            Some("tampered".into()),
            "Modified canary should be detected"
        );
        assert!(
            check_canary_tamper(&tokens[1]).is_none(),
            "Untouched canary should not be flagged"
        );
    }

    #[test]
    fn test_canary_tamper_detection_deleted() {
        let dir = tempfile::TempDir::new().unwrap();
        let tokens = generate_canary_tokens(dir.path()).unwrap();

        std::fs::remove_file(&tokens[0].path).unwrap();

        assert_eq!(
            check_canary_tamper(&tokens[0]),
            Some("deleted".into()),
            "Deleted canary should be detected"
        );
    }

    #[test]
    fn test_pseudo_random_distribution() {
        // Verify different seeds produce different output
        let a = pseudo_random_alphanum(1, 32);
        let b = pseudo_random_alphanum(2, 32);
        let c = pseudo_random_alphanum(1, 32); // Same seed = same output
        assert_ne!(a, b);
        assert_eq!(a, c); // Deterministic for same seed
    }
}
