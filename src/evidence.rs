use crate::monitor::MonitorObservations;

/// A detected access to a canary token file
#[derive(Debug, Clone, serde::Serialize)]
pub struct CanaryAccess {
    pub kind: String,
    pub path: String,
    pub access_type: String,
}

/// Kill chain verdict: correlate canary access with network observations
#[derive(Debug, serde::Serialize)]
pub enum KillChainVerdict {
    /// No suspicious behavior detected
    Pass,
    /// Informational: unexpected network but no credential access
    Info { reason: String },
    /// Warning: credentials accessed but no network exfiltration
    Warn { reason: String },
    /// Block: definitive exfiltration evidence
    Block {
        reason: String,
        canary_kinds: Vec<String>,
        destinations: Vec<String>,
    },
}

/// Evaluate the kill chain: correlate canary access with network observations
pub fn evaluate_kill_chain(
    canary_access: &[CanaryAccess],
    network: &MonitorObservations,
) -> KillChainVerdict {
    let has_canary = !canary_access.is_empty();
    let has_unexpected_net = !network.unexpected.is_empty();
    let has_critical_net = !network.critical.is_empty();

    match (has_canary, has_unexpected_net || has_critical_net) {
        // Credential access + unexpected network = exfiltration
        (true, true) => KillChainVerdict::Block {
            reason: "Credential access + unexpected network connection = exfiltration".into(),
            canary_kinds: canary_access.iter().map(|a| a.kind.clone()).collect(),
            destinations: network
                .unexpected
                .iter()
                .chain(network.critical.iter())
                .map(|c| format!("{}:{}", c.remote_host, c.remote_port))
                .collect(),
        },
        // Credentials accessed but no network — suspicious but not definitive
        (true, false) => KillChainVerdict::Warn {
            reason: "Credentials accessed but no network exfiltration detected".into(),
        },
        // No canary but connection to known-malicious IP (IMDS/cloud metadata)
        (false, true) if has_critical_net => KillChainVerdict::Block {
            reason: "Connection to known-malicious IP (IMDS/cloud metadata)".into(),
            canary_kinds: vec![],
            destinations: network
                .critical
                .iter()
                .map(|c| format!("{}:{}", c.remote_host, c.remote_port))
                .collect(),
        },
        // Unexpected network only — informational
        (false, true) => KillChainVerdict::Info {
            reason: format!(
                "{} unexpected network connection(s)",
                network.unexpected.len()
            ),
        },
        // All clean
        (false, false) => KillChainVerdict::Pass,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::monitor::Connection;

    fn empty_observations() -> MonitorObservations {
        MonitorObservations {
            connections: vec![],
            expected: vec![],
            unexpected: vec![],
            critical: vec![],
            file_alerts: vec![],
            write_violations: vec![],
            duration_secs: 0.0,
        }
    }

    fn make_conn(host: &str, port: u16) -> Connection {
        Connection {
            remote_host: host.into(),
            remote_port: port,
            pid: 1,
            process_name: "node".into(),
            cmdline: String::new(),
        }
    }

    #[test]
    fn test_kill_chain_clean() {
        let verdict = evaluate_kill_chain(&[], &empty_observations());
        assert!(matches!(verdict, KillChainVerdict::Pass));
    }

    #[test]
    fn test_kill_chain_canary_plus_network_blocks() {
        let canary = vec![CanaryAccess {
            kind: "SSH Key".into(),
            path: "/tmp/.ssh/id_rsa".into(),
            access_type: "tampered".into(),
        }];
        let mut obs = empty_observations();
        obs.unexpected.push(make_conn("evil.example.com", 443));
        let verdict = evaluate_kill_chain(&canary, &obs);
        assert!(matches!(verdict, KillChainVerdict::Block { .. }));
    }

    #[test]
    fn test_kill_chain_canary_only_warns() {
        let canary = vec![CanaryAccess {
            kind: "SSH Key".into(),
            path: "/tmp/.ssh/id_rsa".into(),
            access_type: "tampered".into(),
        }];
        let verdict = evaluate_kill_chain(&canary, &empty_observations());
        assert!(matches!(verdict, KillChainVerdict::Warn { .. }));
    }

    #[test]
    fn test_kill_chain_critical_network_blocks() {
        let mut obs = empty_observations();
        obs.critical.push(make_conn("169.254.169.254", 80));
        let verdict = evaluate_kill_chain(&[], &obs);
        assert!(matches!(verdict, KillChainVerdict::Block { .. }));
    }

    #[test]
    fn test_kill_chain_unexpected_network_info() {
        let mut obs = empty_observations();
        obs.unexpected.push(make_conn("unknown-host.com", 443));
        let verdict = evaluate_kill_chain(&[], &obs);
        assert!(matches!(verdict, KillChainVerdict::Info { .. }));
    }
}
