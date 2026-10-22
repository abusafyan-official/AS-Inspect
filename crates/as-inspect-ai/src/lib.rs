use as_inspect_core::{AiAnalysisOutput, AiAnswerItem, AnalysisReport};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiProviderConfig {
    pub endpoint: String,
    pub api_key: String,
    pub model: String,
    pub provider_name: String,
}

#[async_trait]
pub trait AiProvider: Send + Sync {
    async fn explain_evidence(
        &self,
        report: &AnalysisReport,
        questions: &[String],
    ) -> Result<AiAnalysisOutput, String>;
}

pub struct OpenAiCompatibleProvider {
    pub config: AiProviderConfig,
    client: reqwest::Client,
}

impl OpenAiCompatibleProvider {
    pub fn new(config: AiProviderConfig) -> Self {
        Self {
            config,
            client: reqwest::Client::new(),
        }
    }

    pub fn build_evidence_prompt(report: &AnalysisReport, questions: &[String]) -> String {
        let mut prompt = String::new();
        prompt.push_str("You are an evidence-based technical application analyzer.\n");
        prompt.push_str("RULE: You must cite evidence IDs (e.g. EV-...) for all claims. Never invent facts.\n\n");
        prompt.push_str(&format!("Target: {}\n", report.target.filename));
        prompt.push_str(&format!("Size: {} bytes\n\n", report.target.size_bytes));
        prompt.push_str("EVIDENCE COLLECTED:\n");

        for ev in &report.all_evidence {
            prompt.push_str(&format!(
                "- [{}] (Type: {}, Source: {}, Conf: {:?}): {}\n",
                ev.id, ev.r#type, ev.source, ev.confidence, ev.value
            ));
        }

        prompt.push_str("\nQUESTIONS TO ANSWER:\n");
        for (i, q) in questions.iter().enumerate() {
            prompt.push_str(&format!("{}. {}\n", i + 1, q));
        }

        prompt
    }
}

#[async_trait]
impl AiProvider for OpenAiCompatibleProvider {
    async fn explain_evidence(
        &self,
        report: &AnalysisReport,
        questions: &[String],
    ) -> Result<AiAnalysisOutput, String> {
        let prompt = Self::build_evidence_prompt(report, questions);

        let body = serde_json::json!({
            "model": self.config.model,
            "messages": [
                {"role": "system", "content": "You analyze software evidence strictly citing evidence IDs."},
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.2
        });

        let res = self
            .client
            .post(&self.config.endpoint)
            .header("Authorization", format!("Bearer {}", self.config.api_key))
            .json(&body)
            .send()
            .await
            .map_err(|e| format!("HTTP request error: {}", e))?;

        if !res.status().is_success() {
            return Err(format!("AI provider returned error status: {}", res.status()));
        }

        let resp_json: serde_json::Value = res
            .json()
            .await
            .map_err(|e| format!("Failed to parse response JSON: {}", e))?;

        let response_text = resp_json["choices"][0]["message"]["content"]
            .as_str()
            .unwrap_or("No response content")
            .to_string();

        let cited_ids = report
            .all_evidence
            .iter()
            .map(|e| e.id.clone())
            .filter(|id| response_text.contains(id))
            .collect();

        let mut answers = Vec::new();
        for q in questions {
            answers.push(AiAnswerItem {
                question: q.clone(),
                answer: response_text.clone(),
                evidence_ids: cited_ids.clone(),
            });
        }

        Ok(AiAnalysisOutput {
            provider: self.config.provider_name.clone(),
            model: self.config.model.clone(),
            summary: response_text,
            answers,
            cited_evidence_ids: cited_ids,
        })
    }
}
