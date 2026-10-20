//! Shared OpenRouter plumbing. depsec has no chat-LLM tier any more: triage and
//! audit both use the Liquid d1 decision model (see triage_prefilter.rs).

pub(crate) const DEFAULT_BASE_URL: &str = "https://openrouter.ai/api/v1";

/// Token counts per triage result (d1 reports cost directly; kept for the result tuple).
#[allow(dead_code)]
#[derive(Debug, Clone, Default)]
pub struct TokenUsage {
    pub prompt_tokens: u32,
    pub completion_tokens: u32,
    pub total_tokens: u32,
}

pub fn print_setup_instructions() {
    eprintln!("depsec triage/audit requires its own OpenRouter API key (model: liquid/d1-ultra).");
    eprintln!();
    eprintln!("Setup:");
    eprintln!("  1. Get an API key at https://openrouter.ai/keys");
    eprintln!("  2. Set the environment variable:");
    eprintln!("     export DEPSEC_OPENROUTER_API_KEY=sk-or-...");
    eprintln!();
    eprintln!("depsec does not use OPENROUTER_API_KEY unless you opt in:");
    eprintln!("  [triage]");
    eprintln!("  allow_shared_key = true      # or DEPSEC_ALLOW_SHARED_OPENROUTER_KEY=1");
}
