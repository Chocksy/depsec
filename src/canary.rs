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

    // Always place SSH key — most commonly targeted
    let ssh_dir = target_home.join(".ssh");
    std::fs::create_dir_all(&ssh_dir)?;
    let ssh_key = generate_fake_ssh_key(&seed);
    std::fs::write(ssh_dir.join("id_rsa"), &ssh_key)?;
    std::fs::write(ssh_dir.join("id_rsa.pub"), generate_fake_ssh_pubkey(&seed))?;
    tokens.push(CanaryToken {
        path: ssh_dir.join("id_rsa"),
        kind: "SSH Private Key".into(),
    });

    // AWS credentials
    let aws_dir = target_home.join(".aws");
    std::fs::create_dir_all(&aws_dir)?;
    let aws_creds = generate_fake_aws_credentials(&seed);
    std::fs::write(aws_dir.join("credentials"), &aws_creds)?;
    tokens.push(CanaryToken {
        path: aws_dir.join("credentials"),
        kind: "AWS Credentials".into(),
    });

    // .env file with random API keys
    let env_content = generate_fake_env(&seed);
    std::fs::write(target_home.join(".env"), &env_content)?;
    tokens.push(CanaryToken {
        path: target_home.join(".env"),
        kind: "Environment File".into(),
    });

    // .npmrc with fake token (conditionally — randomize)
    if !seed.is_multiple_of(3) {
        let npmrc = generate_fake_npmrc(&seed);
        std::fs::write(target_home.join(".npmrc"), &npmrc)?;
        tokens.push(CanaryToken {
            path: target_home.join(".npmrc"),
            kind: "npm Token".into(),
        });
    }

    // GitHub CLI token (conditionally)
    if seed.is_multiple_of(2) {
        let gh_dir = target_home.join(".config/gh");
        std::fs::create_dir_all(&gh_dir)?;
        let gh_hosts = generate_fake_gh_hosts(&seed);
        std::fs::write(gh_dir.join("hosts.yml"), &gh_hosts)?;
        tokens.push(CanaryToken {
            path: gh_dir.join("hosts.yml"),
            kind: "GitHub CLI Token".into(),
        });
    }

    Ok(tokens)
}

#[derive(Debug, Clone)]
pub struct CanaryToken {
    pub path: PathBuf,
    pub kind: String,
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
    fn test_pseudo_random_distribution() {
        // Verify different seeds produce different output
        let a = pseudo_random_alphanum(1, 32);
        let b = pseudo_random_alphanum(2, 32);
        let c = pseudo_random_alphanum(1, 32); // Same seed = same output
        assert_ne!(a, b);
        assert_eq!(a, c); // Deterministic for same seed
    }
}
