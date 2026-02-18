use std::fs;
use std::path::{Path, PathBuf};

fn collect_rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let mut entries: Vec<PathBuf> = fs::read_dir(dir)
        .expect("read_dir failed")
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .collect();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            if path.file_name().and_then(|n| n.to_str()) == Some("tests") {
                continue;
            }
            collect_rust_files(&path, out);
            continue;
        }
        if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            out.push(path);
        }
    }
}

fn strip_comments_and_literals(input: &str) -> String {
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum State {
        Code,
        LineComment,
        BlockComment,
        StringLiteral,
    }

    let mut out = String::with_capacity(input.len());
    let chars: Vec<char> = input.chars().collect();
    let mut i = 0usize;
    let mut state = State::Code;
    let mut block_depth = 0usize;
    while i < chars.len() {
        let c = chars[i];
        match state {
            State::Code => {
                if c == '/' && i + 1 < chars.len() && chars[i + 1] == '/' {
                    state = State::LineComment;
                    i += 2;
                    continue;
                }
                if c == '/' && i + 1 < chars.len() && chars[i + 1] == '*' {
                    state = State::BlockComment;
                    block_depth = 1;
                    i += 2;
                    continue;
                }
                if c == '"' {
                    state = State::StringLiteral;
                    out.push(' ');
                    i += 1;
                    continue;
                }
                out.push(c);
                i += 1;
            }
            State::LineComment => {
                if c == '\n' {
                    out.push('\n');
                    state = State::Code;
                }
                i += 1;
            }
            State::BlockComment => {
                if c == '/' && i + 1 < chars.len() && chars[i + 1] == '*' {
                    block_depth += 1;
                    i += 2;
                    continue;
                }
                if c == '*' && i + 1 < chars.len() && chars[i + 1] == '/' {
                    block_depth -= 1;
                    i += 2;
                    if block_depth == 0 {
                        state = State::Code;
                    }
                    continue;
                }
                i += 1;
            }
            State::StringLiteral => {
                if c == '\\' {
                    i += 2;
                    continue;
                }
                if c == '"' {
                    state = State::Code;
                }
                i += 1;
            }
        }
    }
    out
}

fn previous_word(source: &str, at: usize) -> Option<&str> {
    if at == 0 {
        return None;
    }
    let bytes = source.as_bytes();
    let mut end = at;
    while end > 0 && bytes[end - 1].is_ascii_whitespace() {
        end -= 1;
    }
    if end == 0 {
        return None;
    }
    let mut start = end;
    while start > 0 {
        let ch = bytes[start - 1];
        if ch.is_ascii_alphanumeric() || ch == b'_' {
            start -= 1;
            continue;
        }
        break;
    }
    if start == end {
        return None;
    }
    Some(&source[start..end])
}

fn count_execute_tool_invocations(source: &str) -> usize {
    let mut total = 0usize;
    let mut offset = 0usize;
    while let Some(rel_pos) = source[offset..].find("execute_tool") {
        let start = offset + rel_pos;
        let after_name = start + "execute_tool".len();
        let mut cursor = after_name;
        let bytes = source.as_bytes();
        while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
            cursor += 1;
        }
        if cursor < bytes.len() && bytes[cursor] == b'(' {
            let is_fn_decl = previous_word(source, start) == Some("fn");
            if !is_fn_decl {
                total += 1;
            }
        }
        offset = after_name;
    }
    total
}

#[test]
fn runtime_execute_tool_chokepoint_is_single_and_route_scoped() {
    let src_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut rust_files = Vec::new();
    collect_rust_files(&src_root, &mut rust_files);

    let mut total_invocations = 0usize;
    let mut invocation_files = Vec::<String>::new();
    for path in rust_files {
        let bytes = fs::read(&path).expect("read source file");
        let raw = String::from_utf8(bytes).expect("utf8 source");
        let cleaned = strip_comments_and_literals(&raw);
        let count = count_execute_tool_invocations(&cleaned);
        if count == 0 {
            continue;
        }
        total_invocations += count;
        let rel = path
            .strip_prefix(&src_root)
            .expect("path under src root")
            .to_string_lossy()
            .replace('\\', "/");
        for _ in 0..count {
            invocation_files.push(rel.clone());
        }
    }

    assert_eq!(
        total_invocations, 1,
        "expected exactly one runtime execute_tool callsite, found {} at {:?}",
        total_invocations, invocation_files
    );
    assert_eq!(
        invocation_files,
        vec!["route/provider_phase.rs".to_string()],
        "execute_tool callsite must remain in route/provider_phase.rs"
    );
}
