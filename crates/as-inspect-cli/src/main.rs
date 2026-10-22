use as_inspect_analyzers::AnalysisPipeline;
use as_inspect_reports::ReportGenerator;
use clap::{Parser, Subcommand};
use std::fs;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "as-inspect")]
#[command(about = "AS Inspect: Understand applications with evidence. Developed by Abu Safyan.", long_about = None)]
#[command(version = "0.1.0")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Perform full technical analysis on a target executable, package, or directory
    Analyze {
        /// Target file or directory to inspect
        target: PathBuf,
        /// Optional path to export JSON report
        #[arg(long)]
        json: Option<PathBuf>,
        /// Optional path to export Markdown report
        #[arg(long)]
        markdown: Option<PathBuf>,
    },
    /// Calculate MD5, SHA-1, and SHA-256 hashes
    Hash {
        target: PathBuf,
    },
    /// Extract printable strings safely
    Strings {
        target: PathBuf,
    },
    /// Inspect PE imports
    Imports {
        target: PathBuf,
    },
    /// Detect framework indicators (Electron, .NET, Python, etc.)
    Detect {
        target: PathBuf,
    },
    /// Generate an inspection report
    Report {
        target: PathBuf,
        #[arg(short, long, default_value = "markdown")]
        format: String,
    },
}

fn main() {
    let cli = Cli::parse();
    let pipeline = AnalysisPipeline::new();

    match cli.command {
        Commands::Analyze { target, json, markdown } => {
            println!("Inspecting: {}", target.display());
            match pipeline.inspect_target(&target) {
                Ok(report) => {
                    println!("\nAnalysis completed successfully!");
                    println!("Total evidence items collected: {}", report.all_evidence.len());
                    for ev in &report.all_evidence {
                        println!("[{}] {} -> {}", ev.id, ev.r#type, ev.value);
                    }

                    if let Some(json_path) = json {
                        if let Ok(content) = ReportGenerator::to_json(&report) {
                            let _ = fs::write(json_path, content);
                            println!("JSON report written.");
                        }
                    }

                    if let Some(md_path) = markdown {
                        let content = ReportGenerator::to_markdown(&report);
                        let _ = fs::write(md_path, content);
                        println!("Markdown report written.");
                    }
                }
                Err(e) => eprintln!("Error analyzing target: {}", e),
            }
        }
        Commands::Hash { target } => {
            match pipeline.inspect_target(&target) {
                Ok(report) => {
                    for ev in &report.all_evidence {
                        if ev.r#type.starts_with("hash_") {
                            println!("{}: {}", ev.r#type.replace("hash_", "").to_uppercase(), ev.value);
                        }
                    }
                }
                Err(e) => eprintln!("Error: {}", e),
            }
        }
        Commands::Strings { target } => {
            match pipeline.inspect_target(&target) {
                Ok(report) => {
                    for ev in &report.all_evidence {
                        if ev.source == "string_scan" {
                            println!("[{}] {}: {}", ev.id, ev.r#type, ev.value);
                        }
                    }
                }
                Err(e) => eprintln!("Error: {}", e),
            }
        }
        Commands::Imports { target } => {
            match pipeline.inspect_target(&target) {
                Ok(report) => {
                    for ev in &report.all_evidence {
                        if ev.r#type == "import_dll" {
                            println!("{}", ev.value);
                        }
                    }
                }
                Err(e) => eprintln!("Error: {}", e),
            }
        }
        Commands::Detect { target } => {
            match pipeline.inspect_target(&target) {
                Ok(report) => {
                    for ev in &report.all_evidence {
                        if ev.r#type == "framework_detection" || ev.r#type == "framework_indicator" {
                            println!("[{}] {}", ev.id, ev.value);
                        }
                    }
                }
                Err(e) => eprintln!("Error: {}", e),
            }
        }
        Commands::Report { target, format } => {
            match pipeline.inspect_target(&target) {
                Ok(report) => {
                    if format == "json" {
                        println!("{}", ReportGenerator::to_json(&report).unwrap_or_default());
                    } else if format == "html" {
                        println!("{}", ReportGenerator::to_html(&report));
                    } else {
                        println!("{}", ReportGenerator::to_markdown(&report));
                    }
                }
                Err(e) => eprintln!("Error: {}", e),
            }
        }
    }
}
