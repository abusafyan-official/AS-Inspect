use as_inspect_analyzers::AnalysisPipeline;
use as_inspect_reports::ReportGenerator;
use serde::{Deserialize, Serialize};
use std::io::{self, BufRead, Write};
use std::path::Path;

#[derive(Deserialize)]
struct JsonRpcRequest {
    jsonrpc: String,
    id: Option<serde_json::Value>,
    method: String,
    params: Option<serde_json::Value>,
}

#[derive(Serialize)]
struct JsonRpcResponse {
    jsonrpc: &'static str,
    id: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<serde_json::Value>,
}

#[tokio::main]
async fn main() {
    let pipeline = AnalysisPipeline::new();
    let stdin = io::stdin();
    let mut stdout = io::stdout();

    for line in stdin.lock().lines() {
        if let Ok(line_str) = line {
            if line_str.trim().is_empty() {
                continue;
            }

            if let Ok(req) = serde_json::from_str::<JsonRpcRequest>(&line_str) {
                let id = req.id.clone();
                match req.method.as_str() {
                    "tools/list" => {
                        let tools = serde_json::json!({
                            "tools": [
                                {
                                    "name": "inspect_file",
                                    "description": "Perform full technical inspection of an executable, archive or folder and extract evidence",
                                    "inputSchema": {
                                        "type": "object",
                                        "properties": {
                                            "path": { "type": "string", "description": "Absolute path to target file or directory" }
                                        },
                                        "required": ["path"]
                                    }
                                },
                                {
                                    "name": "get_hashes",
                                    "description": "Calculate MD5, SHA-1, SHA-256 for target",
                                    "inputSchema": {
                                        "type": "object",
                                        "properties": { "path": { "type": "string" } },
                                        "required": ["path"]
                                    }
                                }
                            ]
                        });
                        let resp = JsonRpcResponse {
                            jsonrpc: "2.0",
                            id,
                            result: Some(tools),
                            error: None,
                        };
                        let _ = writeln!(stdout, "{}", serde_json::to_string(&resp).unwrap());
                        let _ = stdout.flush();
                    }
                    "tools/call" => {
                        let tool_name = req.params.as_ref().and_then(|p| p.get("name")).and_then(|n| n.as_str()).unwrap_or("");
                        let target_path = req.params.as_ref().and_then(|p| p.get("arguments")).and_then(|a| a.get("path")).and_then(|p| p.as_str()).unwrap_or("");

                        if !Path::new(target_path).exists() {
                            let resp = JsonRpcResponse {
                                jsonrpc: "2.0",
                                id,
                                result: None,
                                error: Some(serde_json::json!({
                                    "code": -32602,
                                    "message": format!("Target file not found: {}", target_path)
                                })),
                            };
                            let _ = writeln!(stdout, "{}", serde_json::to_string(&resp).unwrap());
                            let _ = stdout.flush();
                            continue;
                        }

                        match pipeline.inspect_target(target_path) {
                            Ok(report) => {
                                let content = match tool_name {
                                    "get_hashes" => {
                                        let hashes: Vec<_> = report.all_evidence.iter().filter(|e| e.r#type.starts_with("hash_")).collect();
                                        serde_json::to_value(hashes).unwrap()
                                    }
                                    _ => serde_json::to_value(&report).unwrap_or_default(),
                                };

                                let resp = JsonRpcResponse {
                                    jsonrpc: "2.0",
                                    id,
                                    result: Some(serde_json::json!({ "content": [{ "type": "text", "text": content.to_string() }] })),
                                    error: None,
                                };
                                let _ = writeln!(stdout, "{}", serde_json::to_string(&resp).unwrap());
                                let _ = stdout.flush();
                            }
                            Err(e) => {
                                let resp = JsonRpcResponse {
                                    jsonrpc: "2.0",
                                    id,
                                    result: None,
                                    error: Some(serde_json::json!({ "code": -32000, "message": format!("Analysis error: {}", e) })),
                                };
                                let _ = writeln!(stdout, "{}", serde_json::to_string(&resp).unwrap());
                                let _ = stdout.flush();
                            }
                        }
                    }
                    _ => {
                        let resp = JsonRpcResponse {
                            jsonrpc: "2.0",
                            id,
                            result: None,
                            error: Some(serde_json::json!({ "code": -32601, "message": "Method not found" })),
                        };
                        let _ = writeln!(stdout, "{}", serde_json::to_string(&resp).unwrap());
                        let _ = stdout.flush();
                    }
                }
            }
        }
    }
}
