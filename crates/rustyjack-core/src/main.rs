#![deny(unsafe_op_in_unsafe_fn)]
use anyhow::Result;
use clap::Parser;
use rustyjack_core::{dispatch_command, logs_enabled, resolve_root, Cli, OutputFormat};
use serde_json::{json, Value};

fn main() {
    if logs_enabled() {
        let filter = tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
        // Avoid panic if a global subscriber is already set (e.g., accidental double-start).
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .try_init()
            .ok();
    }
    let cli = Cli::parse();
    let format = if cli.json {
        OutputFormat::Json
    } else {
        cli.output_format
    };
    if let Err(err) = run(cli, format) {
        emit_error(format, &err);
        std::process::exit(1);
    }
}

fn run(cli: Cli, output_format: OutputFormat) -> Result<()> {
    let root = resolve_root(cli.root)?;
    let (message, data) = dispatch_command(&root, cli.command)?;
    emit_success(output_format, message, data)
}

fn emit_success(format: OutputFormat, message: String, data: Value) -> Result<()> {
    emit_payload(format, "ok", message, data)
}

fn emit_error(format: OutputFormat, err: &anyhow::Error) {
    let details: Vec<String> = err.chain().map(|cause| cause.to_string()).collect();
    let payload = json!({
        "status": "error",
        "message": err.to_string(),
        "details": details,
        "data": Value::Null,
    });

    match format {
        OutputFormat::Json => println!("{}", payload),
        OutputFormat::Text => {
            eprintln!("Error: {}", err);
            if details.len() > 1 {
                for detail in details.iter().skip(1) {
                    eprintln!("  -> {}", detail);
                }
            }
        }
    }
}

fn emit_payload(format: OutputFormat, status: &str, message: String, data: Value) -> Result<()> {
    let payload = json!({
        "status": status,
        "message": message,
        "data": data,
    });

    match format {
        OutputFormat::Json => println!("{}", payload),
        OutputFormat::Text => {
            println!("{}", payload["message"].as_str().unwrap_or_default());
            if !payload["data"].is_null() {
                let pretty = serde_json::to_string_pretty(&payload["data"])?;
                println!("{pretty}");
            }
        }
    }
    Ok(())
}
