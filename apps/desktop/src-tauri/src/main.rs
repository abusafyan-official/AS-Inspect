// Prevents additional console window on Windows in release
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use as_inspect_analyzers::AnalysisPipeline;
use as_inspect_core::AnalysisReport;
use as_inspect_evidence::EvidenceDatabase;
use as_inspect_reports::ReportGenerator;
use std::path::PathBuf;
use std::sync::Mutex;
use tauri::State;

struct AppState {
    pipeline: AnalysisPipeline,
    db: Mutex<EvidenceDatabase>,
}

#[tauri::command]
fn inspect_target(path: String, state: State<'_, AppState>) -> Result<AnalysisReport, String> {
    let report = state
        .pipeline
        .inspect_target(&path)
        .map_err(|e| format!("Analysis failed: {}", e))?;

    // Auto-save to SQLite evidence database
    if let Ok(db) = state.db.lock() {
        let _ = db.save_report(&report);
    }

    Ok(report)
}

#[tauri::command]
fn export_report(report: AnalysisReport, format: String) -> Result<String, String> {
    match format.as_str() {
        "json" => ReportGenerator::to_json(&report).map_err(|e| e.to_string()),
        "html" => Ok(ReportGenerator::to_html(&report)),
        _ => Ok(ReportGenerator::to_markdown(&report)),
    }
}

#[tauri::command]
fn get_total_analyses(state: State<'_, AppState>) -> Result<i64, String> {
    if let Ok(db) = state.db.lock() {
        db.get_total_analyses_count().map_err(|e| e.to_string())
    } else {
        Err("Failed to acquire database lock".to_string())
    }
}

fn main() {
    let db_path = dirs::data_local_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("ASInspect")
        .join("as_inspect.db");

    if let Some(parent) = db_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    let db = EvidenceDatabase::open(&db_path).unwrap_or_else(|_| EvidenceDatabase::in_memory().unwrap());

    let state = AppState {
        pipeline: AnalysisPipeline::new(),
        db: Mutex::new(db),
    };

    tauri::Builder::default()
        .manage(state)
        .invoke_handler(tauri::generate_handler![
            inspect_target,
            export_report,
            get_total_analyses
        ])
        .run(tauri::generate_context!())
        .expect("error while running AS Inspect tauri application");
}
