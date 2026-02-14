use chrono::{Local, SecondsFormat, TimeZone, Utc};
use std::collections::{HashMap, HashSet};
use std::env;
use std::fs::OpenOptions;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

fn main() {
    std::process::exit(run());
}

fn run() -> i32 {
    let mut args = env::args().skip(1);
    let Some(subcmd) = args.next() else {
        eprintln!("usage: rustyjack-shellops <awk|date|sleep|tr|tee|timeout|socat> ...");
        return 2;
    };

    match subcmd.as_str() {
        "date" => cmd_date(args.collect()),
        "sleep" => cmd_sleep(args.collect()),
        "tr" => cmd_tr(args.collect()),
        "tee" => cmd_tee(args.collect()),
        "timeout" => cmd_timeout(args.collect()),
        "awk" => cmd_awk(args.collect()),
        "socat" => cmd_socat(args.collect()),
        _ => {
            eprintln!("unsupported subcommand: {subcmd}");
            2
        }
    }
}

fn parse_duration(input: &str) -> Result<Duration, String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err("empty duration".to_string());
    }

    if let Some(ms) = trimmed.strip_suffix("ms") {
        let value: f64 = ms
            .parse()
            .map_err(|_| format!("invalid millisecond duration: {trimmed}"))?;
        if value < 0.0 {
            return Err("duration must be >= 0".to_string());
        }
        return Ok(Duration::from_millis(value as u64));
    }

    let (value, mul) = if let Some(v) = trimmed.strip_suffix('h') {
        (v, 3600.0)
    } else if let Some(v) = trimmed.strip_suffix('m') {
        (v, 60.0)
    } else if let Some(v) = trimmed.strip_suffix('s') {
        (v, 1.0)
    } else {
        (trimmed, 1.0)
    };
    let secs: f64 = value
        .parse()
        .map_err(|_| format!("invalid duration: {trimmed}"))?;
    if secs < 0.0 {
        return Err("duration must be >= 0".to_string());
    }
    Ok(Duration::from_secs_f64(secs * mul))
}

fn read_stdin_string() -> io::Result<String> {
    let mut s = String::new();
    io::stdin().read_to_string(&mut s)?;
    Ok(s)
}

fn read_lines(files: &[String]) -> io::Result<Vec<String>> {
    let mut out = Vec::new();
    if files.is_empty() {
        let input = read_stdin_string()?;
        out.extend(input.lines().map(|s| s.to_string()));
        return Ok(out);
    }

    for path in files {
        let file = std::fs::File::open(path)?;
        let reader = BufReader::new(file);
        for line in reader.lines() {
            out.push(line?);
        }
    }
    Ok(out)
}

fn cmd_date(args: Vec<String>) -> i32 {
    let mut utc = false;
    let mut iso_seconds = false;
    let mut format: Option<String> = None;
    let mut epoch_input: Option<i64> = None;

    let mut i = 0usize;
    while i < args.len() {
        match args[i].as_str() {
            "-u" => {
                utc = true;
                i += 1;
            }
            "-Is" | "-Iseconds" => {
                iso_seconds = true;
                i += 1;
            }
            "-d" => {
                if i + 1 >= args.len() {
                    eprintln!("date: -d requires an argument");
                    return 2;
                }
                let value = &args[i + 1];
                if let Some(epoch) = value.strip_prefix('@') {
                    match epoch.parse::<i64>() {
                        Ok(v) => epoch_input = Some(v),
                        Err(_) => {
                            eprintln!("date: invalid epoch in -d argument: {value}");
                            return 2;
                        }
                    }
                } else {
                    eprintln!("date: only -d @<epoch> is supported");
                    return 2;
                }
                i += 2;
            }
            "-r" => {
                if i + 1 >= args.len() {
                    eprintln!("date: -r requires an argument");
                    return 2;
                }
                let value = &args[i + 1];
                match value.parse::<i64>() {
                    Ok(v) => epoch_input = Some(v),
                    Err(_) => {
                        eprintln!("date: only numeric -r <epoch> is supported");
                        return 2;
                    }
                }
                i += 2;
            }
            v if v.starts_with('+') => {
                format = Some(v[1..].to_string());
                i += 1;
            }
            other => {
                eprintln!("date: unsupported arg: {other}");
                return 2;
            }
        }
    }

    let dt_utc = if let Some(epoch) = epoch_input {
        match Utc.timestamp_opt(epoch, 0).single() {
            Some(v) => v,
            None => {
                eprintln!("date: epoch out of range: {epoch}");
                return 2;
            }
        }
    } else {
        Utc::now()
    };

    if iso_seconds {
        if utc {
            println!("{}", dt_utc.to_rfc3339_opts(SecondsFormat::Secs, true));
        } else {
            println!(
                "{}",
                dt_utc
                    .with_timezone(&Local)
                    .to_rfc3339_opts(SecondsFormat::Secs, false)
            );
        }
        return 0;
    }

    if let Some(fmt) = format {
        let secs = dt_utc.timestamp();
        let nanos = dt_utc.timestamp_subsec_nanos();

        if fmt == "%s" {
            println!("{secs}");
            return 0;
        }
        if fmt == "%s%N" {
            println!("{secs}{nanos:09}");
            return 0;
        }

        let fmt = fmt
            .replace("%s", "__RJ_EPOCH__")
            .replace("%N", "__RJ_NANOS__");
        let mut rendered = if utc {
            dt_utc.format(&fmt).to_string()
        } else {
            dt_utc.with_timezone(&Local).format(&fmt).to_string()
        };
        rendered = rendered.replace("__RJ_EPOCH__", &secs.to_string());
        rendered = rendered.replace("__RJ_NANOS__", &format!("{nanos:09}"));
        println!("{rendered}");
        return 0;
    }

    if utc {
        println!("{}", dt_utc.to_rfc3339_opts(SecondsFormat::Secs, true));
    } else {
        println!(
            "{}",
            dt_utc
                .with_timezone(&Local)
                .to_rfc3339_opts(SecondsFormat::Secs, false)
        );
    }
    0
}

fn cmd_sleep(args: Vec<String>) -> i32 {
    if args.len() != 1 {
        eprintln!("sleep: expected exactly one duration argument");
        return 2;
    }
    let duration = match parse_duration(&args[0]) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("sleep: {e}");
            return 2;
        }
    };
    thread::sleep(duration);
    0
}

fn unescape_text(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('n') => out.push('\n'),
                Some('r') => out.push('\r'),
                Some('t') => out.push('\t'),
                Some('\\') => out.push('\\'),
                Some(other) => {
                    out.push('\\');
                    out.push(other);
                }
                None => out.push('\\'),
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn set_chars(spec: &str) -> Vec<char> {
    let unescaped = unescape_text(spec);
    match unescaped.as_str() {
        "[:upper:]" | "A-Z" => ('A'..='Z').collect(),
        "[:lower:]" | "a-z" => ('a'..='z').collect(),
        _ => {
            if unescaped.len() == 3 {
                let chars: Vec<char> = unescaped.chars().collect();
                if chars[1] == '-' {
                    return (chars[0]..=chars[2]).collect();
                }
            }
            unescaped.chars().collect()
        }
    }
}

fn cmd_tr(args: Vec<String>) -> i32 {
    if args.is_empty() {
        eprintln!("tr: missing arguments");
        return 2;
    }

    let stdin = match read_stdin_string() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("tr: failed to read stdin: {e}");
            return 1;
        }
    };

    if args[0] == "-d" {
        if args.len() != 2 {
            eprintln!("tr -d: expected one set argument");
            return 2;
        }
        let drops: HashSet<char> = set_chars(&args[1]).into_iter().collect();
        let result: String = stdin.chars().filter(|c| !drops.contains(c)).collect();
        print!("{result}");
        return 0;
    }

    if args.len() != 2 {
        eprintln!("tr: expected two set arguments");
        return 2;
    }

    let set1 = unescape_text(&args[0]);
    let set2 = unescape_text(&args[1]);

    if (set1 == "[:upper:]" && set2 == "[:lower:]") || (set1 == "A-Z" && set2 == "a-z") {
        let result: String = stdin.chars().map(|c| c.to_ascii_lowercase()).collect();
        print!("{result}");
        return 0;
    }
    if (set1 == "[:lower:]" && set2 == "[:upper:]") || (set1 == "a-z" && set2 == "A-Z") {
        let result: String = stdin.chars().map(|c| c.to_ascii_uppercase()).collect();
        print!("{result}");
        return 0;
    }

    let src = set_chars(&set1);
    let mut dst = set_chars(&set2);
    if src.is_empty() {
        print!("{stdin}");
        return 0;
    }
    if dst.is_empty() {
        dst.push('\0');
    }

    let mut out = String::with_capacity(stdin.len());
    for ch in stdin.chars() {
        if let Some(pos) = src.iter().position(|c| *c == ch) {
            let idx = pos.min(dst.len().saturating_sub(1));
            let mapped = dst[idx];
            if mapped != '\0' {
                out.push(mapped);
            }
        } else {
            out.push(ch);
        }
    }
    print!("{out}");
    0
}

fn cmd_tee(args: Vec<String>) -> i32 {
    let mut append = false;
    let mut files: Vec<String> = Vec::new();

    for arg in args {
        if arg == "-a" {
            append = true;
            continue;
        }
        files.push(arg);
    }

    let mut buf = Vec::new();
    if let Err(e) = io::stdin().read_to_end(&mut buf) {
        eprintln!("tee: failed reading stdin: {e}");
        return 1;
    }

    if let Err(e) = io::stdout().write_all(&buf) {
        eprintln!("tee: failed writing stdout: {e}");
        return 1;
    }
    if let Err(e) = io::stdout().flush() {
        eprintln!("tee: failed flushing stdout: {e}");
        return 1;
    }

    for path in files {
        let mut opts = OpenOptions::new();
        opts.create(true).write(true);
        if append {
            opts.append(true);
        } else {
            opts.truncate(true);
        }
        let mut file = match opts.open(&path) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("tee: failed opening {path}: {e}");
                return 1;
            }
        };
        if let Err(e) = file.write_all(&buf) {
            eprintln!("tee: failed writing {path}: {e}");
            return 1;
        }
    }

    0
}

fn cmd_timeout(args: Vec<String>) -> i32 {
    if args.len() < 2 {
        eprintln!("timeout: usage timeout <duration> <command> [args...]");
        return 2;
    }
    let duration = match parse_duration(&args[0]) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("timeout: {e}");
            return 2;
        }
    };
    let cmd = &args[1];
    let cmd_args = &args[2..];

    let mut child = match Command::new(cmd)
        .args(cmd_args)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("timeout: failed to spawn {cmd}: {e}");
            return 127;
        }
    };

    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                return status.code().unwrap_or(1);
            }
            Ok(None) => {
                if start.elapsed() >= duration {
                    let _ = child.kill();
                    let _ = child.wait();
                    return 124;
                }
                thread::sleep(Duration::from_millis(25));
            }
            Err(e) => {
                eprintln!("timeout: wait failed: {e}");
                let _ = child.kill();
                let _ = child.wait();
                return 1;
            }
        }
    }
}

fn parse_unix_socket_addr(addr: &str) -> Option<String> {
    addr.strip_prefix("UNIX-CONNECT:")
        .or_else(|| addr.strip_prefix("UNIX-CLIENT:"))
        .or_else(|| addr.strip_prefix("UNIX:"))
        .map(ToString::to_string)
}

fn cmd_socat(args: Vec<String>) -> i32 {
    let mut timeout: Option<Duration> = None;
    let mut addresses: Vec<String> = Vec::new();
    let mut i = 0usize;

    while i < args.len() {
        match args[i].as_str() {
            "-t" | "-T" => {
                if i + 1 >= args.len() {
                    eprintln!("socat: {} requires a timeout value", args[i]);
                    return 2;
                }
                let parsed = match parse_duration(&args[i + 1]) {
                    Ok(v) => v,
                    Err(e) => {
                        eprintln!("socat: invalid timeout: {e}");
                        return 2;
                    }
                };
                timeout = Some(parsed);
                i += 2;
            }
            "-" => {
                addresses.push("-".to_string());
                i += 1;
            }
            other if other.starts_with('-') => {
                eprintln!("socat: unsupported option: {other}");
                return 2;
            }
            _ => {
                addresses.push(args[i].clone());
                i += 1;
            }
        }
    }

    if addresses.len() != 2 {
        eprintln!(
            "socat: expected exactly 2 addresses (supports only '-' and UNIX-CONNECT:<path>)"
        );
        return 2;
    }

    let (left, right) = (&addresses[0], &addresses[1]);
    let socket_path = if left == "-" {
        parse_unix_socket_addr(right)
    } else if right == "-" {
        parse_unix_socket_addr(left)
    } else {
        None
    };

    let Some(socket_path) = socket_path else {
        eprintln!("socat: supported forms: '-' UNIX-CONNECT:<path> (or UNIX-CLIENT/UNIX)");
        return 2;
    };

    let mut stream = match UnixStream::connect(&socket_path) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("socat: failed to connect to {socket_path}: {e}");
            return 1;
        }
    };

    if let Some(limit) = timeout {
        let _ = stream.set_read_timeout(Some(limit));
        let _ = stream.set_write_timeout(Some(limit));
    }

    let mut writer = match stream.try_clone() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("socat: failed to clone socket handle: {e}");
            return 1;
        }
    };

    let stdin_to_socket = thread::spawn(move || -> io::Result<()> {
        let mut stdin = io::stdin();
        io::copy(&mut stdin, &mut writer)?;
        let _ = writer.shutdown(Shutdown::Write);
        Ok(())
    });

    let socket_to_stdout = thread::spawn(move || -> io::Result<()> {
        let mut stdout = io::stdout();
        io::copy(&mut stream, &mut stdout)?;
        stdout.flush()?;
        Ok(())
    });

    match stdin_to_socket.join() {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            eprintln!("socat: stdin->socket copy failed: {e}");
            return 1;
        }
        Err(_) => {
            eprintln!("socat: stdin->socket worker panicked");
            return 1;
        }
    }

    match socket_to_stdout.join() {
        Ok(Ok(())) => 0,
        Ok(Err(e)) => {
            eprintln!("socat: socket->stdout copy failed: {e}");
            1
        }
        Err(_) => {
            eprintln!("socat: socket->stdout worker panicked");
            1
        }
    }
}

#[derive(Debug)]
struct AwkArgs {
    field_sep: Option<String>,
    vars: HashMap<String, String>,
    script: String,
    files: Vec<String>,
}

fn parse_awk_args(args: Vec<String>) -> Result<AwkArgs, String> {
    let mut field_sep: Option<String> = None;
    let mut vars = HashMap::new();

    let mut i = 0usize;
    while i < args.len() {
        let arg = &args[i];
        if arg == "-F" {
            if i + 1 >= args.len() {
                return Err("awk: -F requires argument".to_string());
            }
            field_sep = Some(args[i + 1].clone());
            i += 2;
            continue;
        }
        if let Some(fs) = arg.strip_prefix("-F") {
            field_sep = Some(fs.to_string());
            i += 1;
            continue;
        }
        if arg == "-v" {
            if i + 1 >= args.len() {
                return Err("awk: -v requires name=value".to_string());
            }
            let pair = &args[i + 1];
            if let Some((k, v)) = pair.split_once('=') {
                vars.insert(k.to_string(), v.to_string());
            } else {
                return Err(format!("awk: invalid -v assignment: {pair}"));
            }
            i += 2;
            continue;
        }
        if let Some(pair) = arg.strip_prefix("-v") {
            if let Some((k, v)) = pair.split_once('=') {
                vars.insert(k.to_string(), v.to_string());
                i += 1;
                continue;
            }
            return Err(format!("awk: invalid -v assignment: {arg}"));
        }
        break;
    }

    if i >= args.len() {
        return Err("awk: missing program".to_string());
    }

    let script = args[i].clone();
    let files = args[i + 1..].to_vec();
    Ok(AwkArgs {
        field_sep,
        vars,
        script,
        files,
    })
}

fn split_fields(line: &str, fs: Option<&str>) -> Vec<String> {
    match fs {
        None => line
            .split_whitespace()
            .filter(|v| !v.is_empty())
            .map(ToString::to_string)
            .collect(),
        Some(": ") => line.split(": ").map(ToString::to_string).collect(),
        Some(":") => line.split(':').map(ToString::to_string).collect(),
        Some("=") => line.split('=').map(ToString::to_string).collect(),
        Some("[[:space:],]+") => {
            let mut out = Vec::new();
            let mut current = String::new();
            for ch in line.chars() {
                if ch.is_ascii_whitespace() || ch == ',' {
                    if !current.is_empty() {
                        out.push(std::mem::take(&mut current));
                    }
                } else {
                    current.push(ch);
                }
            }
            if !current.is_empty() {
                out.push(current);
            }
            out
        }
        Some(other) => line.split(other).map(ToString::to_string).collect(),
    }
}

fn normalize_script(script: &str) -> String {
    script.chars().filter(|c| !c.is_whitespace()).collect()
}

enum FieldSelector {
    Index(usize),
    Last,
}

fn parse_simple_print_selector(ns: &str) -> Option<FieldSelector> {
    if !(ns.starts_with("{print$") && ns.ends_with('}')) {
        return None;
    }
    let inner = &ns[7..ns.len().saturating_sub(1)];
    if inner == "NF" {
        return Some(FieldSelector::Last);
    }
    let idx = inner.parse::<usize>().ok()?;
    if idx == 0 {
        return None;
    }
    Some(FieldSelector::Index(idx - 1))
}

fn select_field(fields: &[String], selector: &FieldSelector) -> Option<String> {
    match selector {
        FieldSelector::Index(i) => fields.get(*i).cloned(),
        FieldSelector::Last => fields.last().cloned(),
    }
}

fn print_selected_fields(
    lines: Vec<String>,
    fs: Option<&str>,
    selector: &FieldSelector,
) -> Vec<String> {
    let mut out = Vec::new();
    for line in lines {
        let fields = split_fields(&line, fs);
        if let Some(value) = select_field(&fields, selector) {
            out.push(value);
        }
    }
    out
}

fn cmd_awk(args: Vec<String>) -> i32 {
    let awk = match parse_awk_args(args) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{e}");
            return 2;
        }
    };

    let lines = match read_lines(&awk.files) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("awk: failed to read input: {e}");
            return 1;
        }
    };

    let script = awk.script.clone();
    let ns = normalize_script(&script);
    let fs = awk.field_sep.as_deref();
    let mut out: Vec<String> = Vec::new();

    // Consecutive de-dupe with limit (installer/service logs)
    if ns.contains("$0==prev{next}{prev=$0;print;count++}count>=max{exit}")
        || ns.contains("$0==prev{next}{prev=$0;print;count++}count>=80{exit}")
    {
        let max = awk
            .vars
            .get("max")
            .and_then(|v| v.parse::<usize>().ok())
            .or_else(|| {
                if ns.contains("count>=80{exit}") {
                    Some(80)
                } else {
                    None
                }
            })
            .unwrap_or(usize::MAX);
        let mut prev = String::new();
        let mut first = true;
        let mut count = 0usize;
        for line in lines {
            if !first && line == prev {
                continue;
            }
            first = false;
            prev = line.clone();
            out.push(line);
            count += 1;
            if count >= max {
                break;
            }
        }
    } else if let Some(selector) = parse_simple_print_selector(&ns) {
        out = print_selected_fields(lines, fs, &selector);
    } else if ns.contains("$2==\"00000000\"{print$1;exit}") {
        for line in lines {
            let fields = split_fields(&line, fs);
            if fields.len() >= 2 && fields[1] == "00000000" {
                out.push(fields[0].clone());
                break;
            }
        }
    } else if ns.contains("/^Inst/{print$2}") {
        for line in lines {
            let l = line.trim_start();
            if l.starts_with("Inst") {
                let fields = split_fields(l, fs);
                if fields.len() >= 2 {
                    out.push(fields[1].clone());
                }
            }
        }
    } else if ns.contains("/Interface/{print$2}") {
        for line in lines {
            if line.contains("Interface") {
                let fields = split_fields(&line, fs);
                if fields.len() >= 2 {
                    out.push(fields[1].clone());
                }
            }
        }
    } else if ns.contains("/^Swap:/{print$2}") {
        for line in lines {
            if line.starts_with("Swap:") {
                let fields = split_fields(&line, fs);
                if fields.len() >= 2 {
                    out.push(fields[1].clone());
                }
            }
        }
    } else if ns.contains("NF&&!seen[$0]++") {
        let mut seen = HashSet::new();
        for line in lines {
            if line.trim().is_empty() {
                continue;
            }
            if seen.insert(line.clone()) {
                out.push(line);
            }
        }
    } else if ns.contains("for(i=1;i<=NF;i++)if($i!=\"\")print$i") {
        for line in lines {
            for field in split_fields(&line, fs) {
                if !field.is_empty() {
                    out.push(field);
                }
            }
        }
    } else if ns.contains("NR==1{for(i=1;i<=NF;i++)if($i==\"dev\"){print$(i+1);exit}}") {
        if let Some(line) = lines.first() {
            let fields = split_fields(line, fs);
            for i in 0..fields.len() {
                if fields[i] == "dev" && i + 1 < fields.len() {
                    out.push(fields[i + 1].clone());
                    break;
                }
            }
        }
    } else if ns.contains("for(i=1;i<=NF;++i)if($i==\"dev\")print$(i+1)")
        || ns.contains("for(i=1;i<=NF;i++)if($i==\"dev\")print$(i+1)")
    {
        for line in lines {
            let fields = split_fields(&line, fs);
            let mut found = None;
            for i in 0..fields.len() {
                if fields[i] == "dev" && i + 1 < fields.len() {
                    found = Some(fields[i + 1].clone());
                    break;
                }
            }
            if let Some(v) = found {
                out.push(v);
                if ns.contains("exit") {
                    break;
                }
            }
        }
    } else if ns.contains("for(i=1;i<=NF;++i)if($i==\"via\")print$(i+1)")
        || ns.contains("for(i=1;i<=NF;i++)if($i==\"via\")print$(i+1)")
    {
        for line in lines {
            let fields = split_fields(&line, fs);
            let mut found = None;
            for i in 0..fields.len() {
                if fields[i] == "via" && i + 1 < fields.len() {
                    found = Some(fields[i + 1].clone());
                    break;
                }
            }
            if let Some(v) = found {
                out.push(v);
                if ns.contains("exit") {
                    break;
                }
            }
        }
    } else if ns.contains("$2==1&&$3!=\"\"&&$4==\"\"{print$1;exit}") {
        for line in lines {
            let fields = split_fields(&line, fs);
            let f1 = fields.first().map(String::as_str).unwrap_or("");
            let f2 = fields.get(1).map(String::as_str).unwrap_or("");
            let f3 = fields.get(2).map(String::as_str).unwrap_or("");
            let f4 = fields.get(3).map(String::as_str).unwrap_or("");
            if f2 == "1" && !f3.is_empty() && f4.is_empty() {
                out.push(f1.to_string());
                break;
            }
        }
    } else if ns.contains("$4==gid{print$1}") {
        let Some(gid) = awk.vars.get("gid") else {
            eprintln!("awk: gid variable required");
            return 2;
        };
        for line in lines {
            let fields = split_fields(&line, fs);
            if fields.len() >= 4 && fields[3] == *gid {
                out.push(fields[0].clone());
            }
        }
    } else if ns.contains("$1!=\"lo\"{count++}END{printcount+0}") {
        let mut count = 0usize;
        for line in lines {
            let fields = split_fields(&line, fs);
            if !fields.is_empty() && fields[0] != "lo" {
                count += 1;
            }
        }
        out.push(count.to_string());
    } else if script.contains("RUSTYJACKD_OPERATOR_GROUP") && ns.contains("print$2;exit") {
        for line in lines {
            if line.contains("RUSTYJACKD_OPERATOR_GROUP") {
                let fields = split_fields(&line, fs);
                if fields.len() >= 2 {
                    out.push(fields[1].clone());
                    break;
                }
            }
        }
    } else if script.contains("RUSTYJACKD_ADMIN_GROUP") && ns.contains("print$2;exit") {
        for line in lines {
            if line.contains("RUSTYJACKD_ADMIN_GROUP") {
                let fields = split_fields(&line, fs);
                if fields.len() >= 2 {
                    out.push(fields[1].clone());
                    break;
                }
            }
        }
    } else if ns.contains("$2==mp{print$4;exit}") {
        let Some(mp) = awk.vars.get("mp") else {
            eprintln!("awk: mp variable required");
            return 2;
        };
        for line in lines {
            let fields = split_fields(&line, fs);
            if fields.len() >= 4 && fields[1] == *mp {
                out.push(fields[3].clone());
                break;
            }
        }
    } else if ns.contains("{printtoupper($1\":\"$2\":\"$3)}") {
        for line in lines {
            let fields = split_fields(&line, fs);
            if fields.len() >= 3 {
                let value =
                    format!("{}:{}:{}", fields[0], fields[1], fields[2]).to_ascii_uppercase();
                out.push(value);
            }
        }
    } else if ns == "{print$6}" {
        for line in lines {
            let fields = split_fields(&line, fs);
            if fields.len() >= 6 {
                out.push(fields[5].clone());
            }
        }
    } else if script.contains("^- ") && ns.contains("print$2;exit") && awk.vars.contains_key("k") {
        let key = awk.vars.get("k").cloned().unwrap_or_default();
        let needle = format!("- {key}:");
        for line in lines {
            if line.starts_with(&needle) {
                if let Some((_, value)) = line.split_once(": ") {
                    out.push(value.to_string());
                }
                break;
            }
        }
    } else if ns.contains("NR==1{prev=$0;count=1;next}")
        && ns.contains("$0==prev{count++;next}")
        && ns.contains("printprev(count>1?\"(x\"count\")\":\"\")")
    {
        if !lines.is_empty() {
            let mut prev = lines[0].clone();
            let mut count = 1usize;
            for line in lines.iter().skip(1) {
                if *line == prev {
                    count += 1;
                    continue;
                }
                if count > 1 {
                    out.push(format!("{prev} (x{count})"));
                } else {
                    out.push(prev);
                }
                prev = line.clone();
                count = 1;
            }
            if count > 1 {
                out.push(format!("{prev} (x{count})"));
            } else {
                out.push(prev);
            }
        }
    } else {
        eprintln!("awk: unsupported program: {}", awk.script);
        return 2;
    }

    for line in out {
        println!("{line}");
    }
    0
}
