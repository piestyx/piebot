use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

pub(crate) fn validate_runtime_root(path: &Path) -> Result<(), String> {
    if !path.exists() {
        return Err(format!("runtime path does not exist: {}", path.display()));
    }
    if !path.is_dir() {
        return Err(format!(
            "runtime path is not a directory: {}",
            path.display()
        ));
    }
    Ok(())
}

pub(crate) fn list_json_files(dir: &Path) -> io::Result<Vec<PathBuf>> {
    let mut files: Vec<PathBuf> = fs::read_dir(dir)?
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.is_file())
        .collect();
    files.sort_by_key(|a| path_name(a));
    Ok(files)
}

pub(crate) fn read_file_prefix(path: &Path, max: usize) -> io::Result<Vec<u8>> {
    let file = File::open(path)?;
    let mut buf = Vec::new();
    let mut limited = file.take(max as u64);
    limited.read_to_end(&mut buf)?;
    Ok(buf)
}

pub(crate) fn read_file_tail(path: &Path, max: usize) -> io::Result<Vec<u8>> {
    let mut file = File::open(path)?;
    let len = file.metadata()?.len();
    if len <= max as u64 {
        let mut buf = Vec::new();
        file.read_to_end(&mut buf)?;
        return Ok(buf);
    }
    file.seek(SeekFrom::Start(len - max as u64))?;
    let mut buf = Vec::new();
    file.read_to_end(&mut buf)?;
    Ok(buf)
}

pub(crate) fn path_name(path: &Path) -> String {
    path.file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_string()
}
