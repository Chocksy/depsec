use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

const DEFAULT_BASE_URL: &str = "https://openrouter.ai/api/v1";
// Used by from_env() — scaffolded for direct API usage without config file
#[allow(dead_code)]
const DEFAULT_MODEL: &str = "anthropic/claude-sonnet-4-6";
#[allow(dead_code)]
const DEFAULT_TIMEOUT_SECS: u64 = 60;

#[derive(Debug, Clone, Serialize)]
struct ChatRequest {
    model: String,
    messages: Vec<ChatMessage>,
    temperature: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub role: String,
    pub content: String,
}

#[derive(Debug, Deserialize)]
struct ChatResponseRaw {
    choices: Vec<Choice>,
    usage: Option<UsageRaw>,
    model: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Choice {
    message: ChoiceMessage,
}

#[derive(Debug, Deserialize)]
struct ChoiceMessage {
    content: Option<String>,
}

#[derive(Debug, Deserialize)]
struct UsageRaw {
    prompt_tokens: Option<u32>,
    completion_tokens: Option<u32>,
    total_tokens: Option<u32>,
}

pub struct ChatResponse {
    pub content: String,
    #[allow(dead_code)] // Scaffolded — will display model in triage output
    pub model: String,
    pub usage: TokenUsage,
}

#[derive(Debug, Clone, Default)]
pub struct TokenUsage {
    pub prompt_tokens: u32,
    pub completion_tokens: u32,
    pub total_tokens: u32,
}

/// Trait for LLM API interaction — enables mocking in tests
#[cfg_attr(test, mockall::automock)]
pub trait LlmApi {
    fn chat(&self, messages: &[ChatMessage]) -> Result<ChatResponse>;
    fn model(&self) -> &str;
    fn estimate_cost(&self, input_tokens: u32, output_tokens: u32) -> f64;
}

/// Send a chat request and parse the response as JSON.
/// Free function (not on trait) because mockall can't handle generic methods.
pub fn chat_json<T: serde::de::DeserializeOwned>(
    client: &dyn LlmApi,
    messages: &[ChatMessage],
) -> Result<(T, TokenUsage)> {
    let response = client.chat(messages)?;
    let json_str = extract_json(&response.content).unwrap_or_else(|| response.content.clone());
    let parsed: T = serde_json::from_str(&json_str).with_context(|| {
        format!(
            "Failed to parse LLM response as JSON: {}",
            &json_str[..json_str.len().min(200)]
        )
    })?;
    Ok((parsed, response.usage))
}

pub struct LlmClient {
    api_key: String,
    model: String,
    pub(crate) base_url: String,
    timeout_secs: u64,
}

impl LlmClient {
    /// Create client from OPENROUTER_API_KEY environment variable.
    /// Scaffolded public API — used in tests, planned for CLI direct usage.
    #[allow(dead_code)]
    pub fn from_env() -> Option<Self> {
        let api_key = std::env::var("OPENROUTER_API_KEY").ok()?;
        if api_key.is_empty() {
            return None;
        }
        Some(Self {
            api_key,
            model: DEFAULT_MODEL.into(),
            base_url: DEFAULT_BASE_URL.into(),
            timeout_secs: DEFAULT_TIMEOUT_SECS,
        })
    }

    /// Create client from config, falling back to env
    pub fn from_config(config: &crate::config::TriageConfig) -> Option<Self> {
        // Try config's env var name first, then default OPENROUTER_API_KEY
        let api_key = std::env::var(&config.api_key_env)
            .or_else(|_| std::env::var("OPENROUTER_API_KEY"))
            .ok()?;
        if api_key.is_empty() {
            return None;
        }
        Some(Self {
            api_key,
            model: config.model.clone(),
            base_url: DEFAULT_BASE_URL.into(),
            timeout_secs: config.timeout_seconds,
        })
    }

    /// Send a chat completion request and return the response
    fn chat_impl(&self, messages: &[ChatMessage]) -> Result<ChatResponse> {
        let request = ChatRequest {
            model: self.model.clone(),
            messages: messages.to_vec(),
            temperature: 0.1, // Low creativity for classification tasks
        };

        let response = ureq::post(&format!("{}/chat/completions", self.base_url))
            .set("Authorization", &format!("Bearer {}", self.api_key))
            .set("Content-Type", "application/json")
            .set("HTTP-Referer", "https://github.com/chocksy/depsec")
            .set("X-Title", "depsec")
            .timeout(std::time::Duration::from_secs(self.timeout_secs))
            .send_json(&request)
            .context("Failed to send request to OpenRouter")?;

        let raw: ChatResponseRaw = response
            .into_json()
            .context("Failed to parse OpenRouter response")?;

        let content = raw
            .choices
            .first()
            .and_then(|c| c.message.content.clone())
            .unwrap_or_default();

        let usage = raw.usage.map_or(TokenUsage::default(), |u| TokenUsage {
            prompt_tokens: u.prompt_tokens.unwrap_or(0),
            completion_tokens: u.completion_tokens.unwrap_or(0),
            total_tokens: u.total_tokens.unwrap_or(0),
        });

        Ok(ChatResponse {
            content,
            model: raw.model.unwrap_or_else(|| self.model.clone()),
            usage,
        })
    }

    /// Rough cost estimate in USD based on model pricing
    fn estimate_cost_impl(&self, input_tokens: u32, output_tokens: u32) -> f64 {
        // Approximate pricing per 1M tokens (as of 2026)
        let (input_per_m, output_per_m) = match self.model.as_str() {
            m if m.contains("claude-sonnet") => (3.0, 15.0),
            m if m.contains("claude-haiku") => (0.80, 4.0),
            m if m.contains("claude-opus") => (15.0, 75.0),
            m if m.contains("gpt-4o") => (2.50, 10.0),
            _ => (3.0, 15.0), // Default to Sonnet-ish pricing
        };

        (input_tokens as f64 / 1_000_000.0) * input_per_m
            + (output_tokens as f64 / 1_000_000.0) * output_per_m
    }
}

impl LlmApi for LlmClient {
    fn chat(&self, messages: &[ChatMessage]) -> Result<ChatResponse> {
        self.chat_impl(messages)
    }

    fn model(&self) -> &str {
        &self.model
    }

    fn estimate_cost(&self, input_tokens: u32, output_tokens: u32) -> f64 {
        self.estimate_cost_impl(input_tokens, output_tokens)
    }
}

/// Extract JSON from a response that might be wrapped in markdown code blocks
fn extract_json(content: &str) -> Option<String> {
    let trimmed = content.trim();

    // Already looks like JSON
    if trimmed.starts_with('{') || trimmed.starts_with('[') {
        return Some(trimmed.to_string());
    }

    // Extract from ```json ... ``` blocks
    if let Some(start) = trimmed.find("```json") {
        let after_marker = &trimmed[start + 7..];
        if let Some(end) = after_marker.find("```") {
            return Some(after_marker[..end].trim().to_string());
        }
    }

    // Extract from ``` ... ``` blocks
    if let Some(start) = trimmed.find("```") {
        let after_marker = &trimmed[start + 3..];
        // Skip to next line
        if let Some(newline) = after_marker.find('\n') {
            let content_start = &after_marker[newline + 1..];
            if let Some(end) = content_start.find("```") {
                return Some(content_start[..end].trim().to_string());
            }
        }
    }

    // Last resort: find first { and last } — handles preamble text before JSON
    if let (Some(start), Some(end)) = (trimmed.find('{'), trimmed.rfind('}')) {
        if end > start {
            return Some(trimmed[start..=end].to_string());
        }
    }

    None
}

/// Print setup instructions when API key is missing
pub fn print_setup_instructions() {
    eprintln!("LLM triage requires an OpenRouter API key.");
    eprintln!();
    eprintln!("Setup:");
    eprintln!("  1. Get an API key at https://openrouter.ai/keys");
    eprintln!("  2. Set the environment variable:");
    eprintln!("     export OPENROUTER_API_KEY=sk-or-...");
    eprintln!();
    eprintln!("Or configure in depsec.toml:");
    eprintln!("  [triage]");
    eprintln!("  api_key_env = \"OPENROUTER_API_KEY\"");
    eprintln!("  model = \"anthropic/claude-sonnet-4-6\"");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_json_raw() {
        let input = r#"{"classification": "TP", "confidence": 0.9}"#;
        assert_eq!(extract_json(input), Some(input.to_string()));
    }

    #[test]
    fn test_extract_json_code_block() {
        let input = "Here's the analysis:\n```json\n{\"classification\": \"FP\"}\n```\n";
        assert_eq!(
            extract_json(input),
            Some("{\"classification\": \"FP\"}".to_string())
        );
    }

    #[test]
    fn test_extract_json_bare_block() {
        let input = "```\n{\"classification\": \"NI\"}\n```";
        assert_eq!(
            extract_json(input),
            Some("{\"classification\": \"NI\"}".to_string())
        );
    }

    #[test]
    fn test_extract_json_no_json() {
        let input = "This is just text with no JSON";
        assert_eq!(extract_json(input), None);
    }

    #[test]
    fn test_estimate_cost_sonnet() {
        let client = LlmClient {
            api_key: "test".into(),
            model: "anthropic/claude-sonnet-4-6".into(),
            base_url: DEFAULT_BASE_URL.into(),
            timeout_secs: 60,
        };
        // 1000 input + 500 output tokens
        let cost = LlmApi::estimate_cost(&client, 1000, 500);
        assert!(cost > 0.0);
        assert!(cost < 0.02); // Should be fractions of a cent for small requests
    }

    #[test]
    fn test_from_env_missing() {
        std::env::remove_var("OPENROUTER_API_KEY");
        assert!(LlmClient::from_env().is_none());
    }

    // --- httpmock tests for LlmClient ---
    use httpmock::prelude::*;

    fn test_client(base_url: &str) -> LlmClient {
        LlmClient {
            api_key: "test-key".into(),
            model: "test-model".into(),
            base_url: base_url.into(),
            timeout_secs: 5,
        }
    }

    #[test]
    fn test_chat_parses_response() {
        let server = MockServer::start();

        server.mock(|when, then| {
            when.method(POST).path("/chat/completions");
            then.status(200)
                .json_body(serde_json::json!({
                    "choices": [{"message": {"content": "Hello!"}}],
                    "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
                    "model": "test-model"
                }));
        });

        let client = test_client(&server.url(""));
        let response = client.chat(&[ChatMessage { role: "user".into(), content: "Hi".into() }]).unwrap();
        assert_eq!(response.content, "Hello!");
        assert_eq!(response.usage.total_tokens, 15);
    }

    #[test]
    fn test_chat_handles_api_error() {
        let server = MockServer::start();

        server.mock(|when, then| {
            when.method(POST).path("/chat/completions");
            then.status(500).body("Internal Server Error");
        });

        let client = test_client(&server.url(""));
        let result = client.chat(&[ChatMessage { role: "user".into(), content: "Hi".into() }]);
        assert!(result.is_err());
    }

    #[test]
    fn test_chat_json_parses_json_response() {
        let server = MockServer::start();

        server.mock(|when, then| {
            when.method(POST).path("/chat/completions");
            then.status(200)
                .json_body(serde_json::json!({
                    "choices": [{"message": {"content": "{\"value\": 42}"}}],
                    "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}
                }));
        });

        let client = test_client(&server.url(""));
        let (parsed, usage): (serde_json::Value, _) = chat_json(
            &client,
            &[ChatMessage { role: "user".into(), content: "give json".into() }],
        ).unwrap();

        assert_eq!(parsed["value"], 42);
        assert_eq!(usage.total_tokens, 15);
    }

    #[test]
    fn test_chat_json_handles_markdown_wrapped() {
        let server = MockServer::start();

        server.mock(|when, then| {
            when.method(POST).path("/chat/completions");
            then.status(200)
                .json_body(serde_json::json!({
                    "choices": [{"message": {"content": "```json\n{\"value\": 99}\n```"}}],
                    "usage": {}
                }));
        });

        let client = test_client(&server.url(""));
        let (parsed, _): (serde_json::Value, _) = chat_json(
            &client,
            &[ChatMessage { role: "user".into(), content: "test".into() }],
        ).unwrap();

        assert_eq!(parsed["value"], 99);
    }

    #[test]
    fn test_estimate_cost_models() {
        let haiku = LlmClient { api_key: "t".into(), model: "claude-haiku-x".into(), base_url: "".into(), timeout_secs: 1 };
        let opus = LlmClient { api_key: "t".into(), model: "claude-opus-x".into(), base_url: "".into(), timeout_secs: 1 };
        let gpt = LlmClient { api_key: "t".into(), model: "gpt-4o-mini".into(), base_url: "".into(), timeout_secs: 1 };

        let h_cost = LlmApi::estimate_cost(&haiku, 1000, 500);
        let o_cost = LlmApi::estimate_cost(&opus, 1000, 500);
        let g_cost = LlmApi::estimate_cost(&gpt, 1000, 500);

        assert!(o_cost > h_cost); // Opus should be more expensive
        assert!(g_cost > h_cost); // GPT-4o more than Haiku
    }

    #[test]
    fn test_extract_json_preamble() {
        let input = "Here is my analysis:\n{\"result\": true}";
        assert_eq!(extract_json(input), Some("{\"result\": true}".to_string()));
    }
}
