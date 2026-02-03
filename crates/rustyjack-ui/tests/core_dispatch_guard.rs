use std::fs;
use std::path::{Path, PathBuf};

fn collect_rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                collect_rs_files(&path, out);
            } else if path.extension().and_then(|ext| ext.to_str()) == Some("rs") {
                out.push(path);
            }
        }
    }
}

#[test]
fn ui_does_not_reference_core_dispatch() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let src_dir = manifest_dir.join("src");
    let mut files = Vec::new();
    collect_rs_files(&src_dir, &mut files);

    let mut offenders = Vec::new();
    for file in files {
        let content = fs::read_to_string(&file).unwrap_or_else(|_| String::new());
        if content.contains("CoreDispatch")
            || content.contains("core_dispatch(")
            || content.contains("LegacyCommand")
        {
            offenders.push(file);
        }
    }

    assert!(
        offenders.is_empty(),
        "UI source must not reference core dispatch. Offenders: {offenders:?}"
    );
}
