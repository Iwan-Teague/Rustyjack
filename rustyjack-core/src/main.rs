use anyhow::Result;
use clap::Parser;
use rustyjack_core::{dispatch_command, logs_enabled, resolve_root, Cli, OutputFormat};
use serde_json::{json, Value};

fn main() {
    if logs_enabled() {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
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
