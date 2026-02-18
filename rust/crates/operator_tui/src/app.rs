use crate::commands::{handle_log_line, stop_process};
use crate::config::{ACTION_COUNT, TICK_MILLIS};
use crate::data::audit_read::apply_audit_filter;
use crate::data::runtime::{list_json_files, path_name, validate_runtime_root};
use crate::model::{ActionsFocus, App, LogsFocus, Tab, Theme};
use crate::tabs;
use crate::tabs::actions::{actions_focus_for_action, actions_focus_is_input};
use crate::tabs::run::run_move_selection;
use crate::ui::draw_ui;
use crossterm::event::{self, Event, KeyCode};
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;
use serde_json::Value;
use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom};
use std::sync::mpsc::TryRecvError;
use std::time::{Duration, Instant};

pub(crate) fn detail_scroll_mut(app: &mut App, tab: Tab) -> &mut usize {
    &mut app.detail_scrolls[tab.index()]
}

pub(crate) fn list_offset_mut(app: &mut App, tab: Tab) -> &mut usize {
    &mut app.list_offsets[tab.index()]
}

pub(crate) fn detail_height(app: &App, tab: Tab) -> usize {
    app.detail_heights[tab.index()]
}

pub(crate) fn set_detail_height(app: &mut App, tab: Tab, height: usize) {
    app.detail_heights[tab.index()] = height;
}

fn clamp_selection(selected: &mut usize, len: usize) {
    if len == 0 {
        *selected = 0;
    } else if *selected >= len {
        *selected = len - 1;
    }
}

pub(crate) fn scroll_detail(app: &mut App, direction: i32) {
    let height = detail_height(app, app.active_tab);
    let step = if height > 0 {
        std::cmp::max(1, height / 2)
    } else {
        5
    };
    let scroll = detail_scroll_mut(app, app.active_tab);
    if direction < 0 {
        *scroll = scroll.saturating_sub(step);
    } else {
        *scroll = scroll.saturating_add(step);
    }
    if app.active_tab == Tab::Audit {
        app.follow_audit = false;
    }
}

pub(crate) fn scroll_logs(app: &mut App, direction: i32) {
    let (height, scroll) = match app.logs_focus {
        LogsFocus::Process => (app.logs_process_height, &mut app.logs_process_scroll),
        LogsFocus::Files => (app.logs_file_height, &mut app.logs_file_scroll),
    };
    let step = if height > 0 {
        std::cmp::max(1, height / 2)
    } else {
        5
    };
    if direction < 0 {
        *scroll = scroll.saturating_sub(step);
    } else {
        *scroll = scroll.saturating_add(step);
    }
}

pub(crate) fn jump_to_top(app: &mut App) {
    match app.active_tab {
        Tab::Run => match app.run.focus {
            crate::model::RunFocus::Skill => app.run.skill_selected = 0,
            crate::model::RunFocus::Mode => app.run.mode_selected = 0,
            _ => {}
        },
        Tab::Audit => app.audit.selected = 0,
        Tab::Artifacts => app.artifacts.selected = 0,
        Tab::Capsule => app.capsule.selected = 0,
        Tab::Explain => app.explain.selected = 0,
        Tab::Skills => app.skills.selected = 0,
        Tab::Logs => app.logs.selected = 0,
        Tab::Actions => {
            app.actions.selected_action = 0;
            app.actions.focus = ActionsFocus::ApproveTool;
        }
    }
    if app.active_tab == Tab::Logs {
        match app.logs_focus {
            LogsFocus::Process => app.logs_process_scroll = 0,
            LogsFocus::Files => app.logs_file_scroll = 0,
        }
    } else {
        *detail_scroll_mut(app, app.active_tab) = 0;
    }
    *list_offset_mut(app, app.active_tab) = 0;
    if app.active_tab == Tab::Audit {
        app.follow_audit = false;
    }
}

pub(crate) fn jump_to_bottom(app: &mut App) {
    let len = match app.active_tab {
        Tab::Run => match app.run.focus {
            crate::model::RunFocus::Skill => app.run.skill_ids.len(),
            crate::model::RunFocus::Mode => 2,
            _ => 0,
        },
        Tab::Audit => app.audit.filtered_indices.len(),
        Tab::Artifacts => app.artifacts.entries.len(),
        Tab::Capsule => app.capsule.entries.len(),
        Tab::Explain => app.explain.entries.len(),
        Tab::Skills => app.skills.entries.len(),
        Tab::Logs => app.logs.entries.len(),
        Tab::Actions => ACTION_COUNT,
    };
    if len == 0 {
        return;
    }
    let last = len - 1;
    match app.active_tab {
        Tab::Run => match app.run.focus {
            crate::model::RunFocus::Skill => app.run.skill_selected = last,
            crate::model::RunFocus::Mode => app.run.mode_selected = last,
            _ => {}
        },
        Tab::Audit => app.audit.selected = last,
        Tab::Artifacts => app.artifacts.selected = last,
        Tab::Capsule => app.capsule.selected = last,
        Tab::Explain => app.explain.selected = last,
        Tab::Skills => app.skills.selected = last,
        Tab::Logs => app.logs.selected = last,
        Tab::Actions => {
            app.actions.selected_action = last;
            app.actions.focus = actions_focus_for_action(last);
        }
    }
    if app.active_tab == Tab::Logs {
        match app.logs_focus {
            LogsFocus::Process => app.logs_process_scroll = usize::MAX,
            LogsFocus::Files => app.logs_file_scroll = usize::MAX,
        }
    } else {
        *detail_scroll_mut(app, app.active_tab) = usize::MAX;
    }
    *list_offset_mut(app, app.active_tab) = usize::MAX;
    if app.active_tab == Tab::Audit {
        app.follow_audit = true;
    }
}

pub(crate) fn move_selection(app: &mut App, delta: i32) {
    if app.active_tab == Tab::Run {
        run_move_selection(app, delta);
        return;
    }
    if app.active_tab == Tab::Logs && matches!(app.logs_focus, LogsFocus::Process) {
        let show_process = app.process.running
            || app.process.exit_status.is_some()
            || !app.process.output.is_empty();
        if show_process {
            return;
        }
        app.logs_focus = LogsFocus::Files;
    }
    let (selected, len) = match app.active_tab {
        Tab::Audit => (app.audit.selected, app.audit.filtered_indices.len()),
        Tab::Artifacts => (app.artifacts.selected, app.artifacts.entries.len()),
        Tab::Capsule => (app.capsule.selected, app.capsule.entries.len()),
        Tab::Explain => (app.explain.selected, app.explain.entries.len()),
        Tab::Skills => (app.skills.selected, app.skills.entries.len()),
        Tab::Logs => (app.logs.selected, app.logs.entries.len()),
        Tab::Actions => (app.actions.selected_action, ACTION_COUNT),
        Tab::Run => (0, 0),
    };
    if len == 0 {
        return;
    }
    let prev = selected;
    let mut next = selected as i32 + delta;
    if next < 0 {
        next = 0;
    }
    if next as usize >= len {
        next = (len - 1) as i32;
    }
    match app.active_tab {
        Tab::Audit => app.audit.selected = next as usize,
        Tab::Artifacts => app.artifacts.selected = next as usize,
        Tab::Capsule => app.capsule.selected = next as usize,
        Tab::Explain => app.explain.selected = next as usize,
        Tab::Skills => app.skills.selected = next as usize,
        Tab::Logs => app.logs.selected = next as usize,
        Tab::Actions => {
            app.actions.selected_action = next as usize;
            if prev != next as usize {
                app.actions.focus = actions_focus_for_action(next as usize);
                app.actions.error = None;
            }
        }
        Tab::Run => {}
    }
    if prev != next as usize {
        if app.active_tab == Tab::Logs {
            app.logs_file_scroll = 0;
        } else {
            *detail_scroll_mut(app, app.active_tab) = 0;
        }
        if app.active_tab == Tab::Audit {
            app.follow_audit = false;
        }
    }
}

fn handle_key(app: &mut App, key: crossterm::event::KeyEvent) {
    if app.active_tab == Tab::Actions && actions_focus_is_input(app.actions.focus) {
        if tabs::handle_current_tab_key(app, key) {
            return;
        }
        return;
    }
    if key.code == KeyCode::Char('q') {
        app.should_quit = true;
        return;
    }
    if tabs::handle_current_tab_key(app, key) {
        return;
    }
    if app.active_tab == Tab::Logs {
        match key.code {
            KeyCode::Tab | KeyCode::BackTab => {
                let show_process = app.process.running
                    || app.process.exit_status.is_some()
                    || !app.process.output.is_empty();
                if show_process {
                    app.logs_focus = match app.logs_focus {
                        LogsFocus::Process => LogsFocus::Files,
                        LogsFocus::Files => LogsFocus::Process,
                    };
                } else {
                    app.logs_focus = LogsFocus::Files;
                }
                return;
            }
            _ => {}
        }
    }
    match key.code {
        KeyCode::Char('1') => app.active_tab = Tab::Run,
        KeyCode::Char('2') => app.active_tab = Tab::Audit,
        KeyCode::Char('3') => app.active_tab = Tab::Artifacts,
        KeyCode::Char('4') => app.active_tab = Tab::Capsule,
        KeyCode::Char('5') => app.active_tab = Tab::Explain,
        KeyCode::Char('6') => app.active_tab = Tab::Skills,
        KeyCode::Char('7') => app.active_tab = Tab::Logs,
        KeyCode::Char('8') => app.active_tab = Tab::Actions,
        KeyCode::Char('j') | KeyCode::Down => move_selection(app, 1),
        KeyCode::Char('k') | KeyCode::Up => move_selection(app, -1),
        KeyCode::PageUp => {
            if app.active_tab == Tab::Logs {
                scroll_logs(app, -1)
            } else {
                scroll_detail(app, -1)
            }
        }
        KeyCode::PageDown => {
            if app.active_tab == Tab::Logs {
                scroll_logs(app, 1)
            } else {
                scroll_detail(app, 1)
            }
        }
        KeyCode::Char('g') => jump_to_top(app),
        KeyCode::Char('G') => jump_to_bottom(app),
        KeyCode::Enter => {}
        KeyCode::Char('/') => {
            if app.active_tab == Tab::Audit {
                app.filter_mode = true;
                app.filter_input = app.audit.filter.clone();
            }
        }
        KeyCode::Char('r') => app.manual_refresh = true,
        _ => {}
    }
}

pub(crate) fn run_app(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut App,
) -> Result<(), Box<dyn std::error::Error>> {
    let tick_rate = Duration::from_millis(TICK_MILLIS);
    let mut last_tick = Instant::now();
    let theme = Theme::new();
    loop {
        let timeout = tick_rate.saturating_sub(last_tick.elapsed());
        if event::poll(timeout)? {
            if let Event::Key(key) = event::read()? {
                if app.filter_mode {
                    tabs::audit::handle_filter_input(app, key);
                } else {
                    handle_key(app, key);
                }
            }
        }
        app.refresh_process();
        if app.manual_refresh || last_tick.elapsed() >= tick_rate {
            app.refresh_all();
            app.manual_refresh = false;
            last_tick = Instant::now();
        }
        terminal.draw(|f| draw_ui(f, app, &theme))?;
        if app.should_quit {
            stop_process(app);
            break;
        }
    }
    Ok(())
}

impl App {
    pub(crate) fn refresh_all(&mut self) {
        match validate_runtime_root(&self.runtime_root) {
            Ok(()) => {
                self.runtime_valid = true;
                self.runtime_error = None;
            }
            Err(err) => {
                self.runtime_valid = false;
                self.runtime_error = Some(err);
                return;
            }
        }
        self.refresh_audit();
        self.refresh_artifacts();
        self.refresh_capsules();
        self.refresh_explains();
        self.refresh_skills();
        self.refresh_logs();
    }

    pub(crate) fn refresh_audit(&mut self) {
        let state = &mut self.audit;
        let prev_len = state.events.len();
        if !state.path.is_file() {
            state.missing = true;
            state.error = None;
            state.events.clear();
            state.filtered_indices.clear();
            state.offset = 0;
            state.partial.clear();
            return;
        }
        state.missing = false;
        state.error = None;
        let meta = match fs::metadata(&state.path) {
            Ok(meta) => meta,
            Err(e) => {
                state.error = Some(format!("audit metadata read failed: {}", e));
                return;
            }
        };
        let file_len = meta.len();
        if file_len < state.offset {
            state.offset = 0;
            state.partial.clear();
            state.events.clear();
        }
        if file_len == state.offset {
            return;
        }
        let mut file = match File::open(&state.path) {
            Ok(file) => file,
            Err(e) => {
                state.error = Some(format!("audit open failed: {}", e));
                return;
            }
        };
        if file.seek(SeekFrom::Start(state.offset)).is_err() {
            state.error = Some("audit seek failed".to_string());
            return;
        }
        let mut buf = Vec::new();
        if file.read_to_end(&mut buf).is_err() {
            state.error = Some("audit read failed".to_string());
            return;
        }
        state.offset += buf.len() as u64;
        let mut combined = state.partial.clone();
        combined.push_str(&String::from_utf8_lossy(&buf));
        state.partial.clear();
        let mut lines: Vec<&str> = combined.split('\n').collect();
        if !combined.ends_with('\n') {
            if let Some(last) = lines.pop() {
                state.partial = last.to_string();
            }
        }
        for line in lines {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            match serde_json::from_str::<Value>(trimmed) {
                Ok(value) => state.events.push(value),
                Err(_) => state.error_count += 1,
            }
        }
        apply_audit_filter(state);
        if self.follow_audit && state.events.len() > prev_len && !state.filtered_indices.is_empty()
        {
            state.selected = state.filtered_indices.len() - 1;
            *list_offset_mut(self, Tab::Audit) = usize::MAX;
            *detail_scroll_mut(self, Tab::Audit) = 0;
        }
    }

    pub(crate) fn refresh_artifacts(&mut self) {
        let dir = self.runtime_root.join("artifacts");
        if !dir.is_dir() {
            self.artifacts.missing = true;
            self.artifacts.error = None;
            self.artifacts.entries.clear();
            return;
        }
        self.artifacts.missing = false;
        self.artifacts.error = None;
        let mut namespaces: Vec<(String, std::path::PathBuf)> = Vec::new();
        let read_dir = match fs::read_dir(&dir) {
            Ok(rd) => rd,
            Err(e) => {
                self.artifacts.error = Some(format!("artifacts read failed: {}", e));
                return;
            }
        };
        for entry in read_dir.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                    namespaces.push((name.to_string(), path));
                }
            }
        }
        namespaces.sort_by(|a, b| a.0.cmp(&b.0));
        let mut entries = Vec::new();
        for (name, path) in namespaces {
            entries.push(crate::model::ArtifactEntry {
                display: format!("{}/", name),
                path: path.clone(),
                is_dir: true,
            });
            let mut files: Vec<(String, std::path::PathBuf)> = Vec::new();
            if let Ok(dir_entries) = fs::read_dir(&path) {
                for entry in dir_entries.flatten() {
                    let file_path = entry.path();
                    if file_path.is_file() {
                        if let Some(fname) = file_path.file_name().and_then(|n| n.to_str()) {
                            files.push((fname.to_string(), file_path));
                        }
                    }
                }
            }
            files.sort_by(|a, b| a.0.cmp(&b.0));
            for (fname, fpath) in files {
                entries.push(crate::model::ArtifactEntry {
                    display: format!("  {}", fname),
                    path: fpath,
                    is_dir: false,
                });
            }
        }
        self.artifacts.entries = entries;
        clamp_selection(&mut self.artifacts.selected, self.artifacts.entries.len());
    }

    pub(crate) fn refresh_capsules(&mut self) {
        let dir = self.runtime_root.join("artifacts").join("run_capsules");
        if !dir.is_dir() {
            self.capsule.missing = true;
            self.capsule.error = None;
            self.capsule.entries.clear();
            return;
        }
        self.capsule.missing = false;
        self.capsule.error = None;
        self.capsule.entries = list_json_files(&dir).unwrap_or_else(|e| {
            self.capsule.error = Some(format!("capsules read failed: {}", e));
            Vec::new()
        });
        clamp_selection(&mut self.capsule.selected, self.capsule.entries.len());
    }

    pub(crate) fn refresh_explains(&mut self) {
        let dir = self.runtime_root.join("artifacts").join("explains");
        if !dir.is_dir() {
            self.explain.missing = true;
            self.explain.error = None;
            self.explain.entries.clear();
            return;
        }
        self.explain.missing = false;
        self.explain.error = None;
        self.explain.entries = list_json_files(&dir).unwrap_or_else(|e| {
            self.explain.error = Some(format!("explains read failed: {}", e));
            Vec::new()
        });
        clamp_selection(&mut self.explain.selected, self.explain.entries.len());
    }

    pub(crate) fn refresh_skills(&mut self) {
        let runtime_skills = self.runtime_root.join("skills");
        let skills_root = if runtime_skills.is_dir() {
            runtime_skills
        } else if let Some(path) = self.skills_dir.as_ref() {
            path.clone()
        } else {
            self.skills.missing = true;
            self.skills.error = None;
            self.skills.entries.clear();
            return;
        };
        if !skills_root.is_dir() {
            self.skills.missing = true;
            self.skills.error = None;
            self.skills.entries.clear();
            return;
        }
        self.skills.missing = false;
        self.skills.error = None;
        let mut entries: Vec<crate::model::SkillEntry> = Vec::new();
        let read_dir = match fs::read_dir(&skills_root) {
            Ok(rd) => rd,
            Err(e) => {
                self.skills.error = Some(format!("skills read failed: {}", e));
                return;
            }
        };
        let mut dirs: Vec<std::path::PathBuf> = read_dir
            .flatten()
            .map(|entry| entry.path())
            .filter(|path| path.is_dir())
            .collect();
        dirs.sort_by(|a, b| path_name(a).cmp(&path_name(b)));
        for path in dirs {
            let dir_name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("unknown")
                .to_string();
            let manifest_path = path.join("skill.json");
            if !manifest_path.is_file() {
                entries.push(crate::model::SkillEntry {
                    id: dir_name,
                    manifest: None,
                    manifest_hash: None,
                    error: Some("skill.json missing".to_string()),
                });
                continue;
            }
            match fs::read(&manifest_path) {
                Ok(bytes) => match serde_json::from_slice::<Value>(&bytes) {
                    Ok(value) => {
                        let hash = pie_common::canonical_json_bytes(&value)
                            .ok()
                            .map(|b| pie_common::sha256_bytes(&b));
                        entries.push(crate::model::SkillEntry {
                            id: dir_name,
                            manifest: Some(value),
                            manifest_hash: hash,
                            error: None,
                        });
                    }
                    Err(_) => entries.push(crate::model::SkillEntry {
                        id: dir_name,
                        manifest: None,
                        manifest_hash: None,
                        error: Some("skill manifest invalid".to_string()),
                    }),
                },
                Err(e) => entries.push(crate::model::SkillEntry {
                    id: dir_name,
                    manifest: None,
                    manifest_hash: None,
                    error: Some(format!("skill manifest read failed: {}", e)),
                }),
            }
        }
        self.skills.entries = entries;
        clamp_selection(&mut self.skills.selected, self.skills.entries.len());
        self.run.skill_ids = self
            .skills
            .entries
            .iter()
            .map(|entry| entry.id.clone())
            .collect();
        if self.run.skill_selected >= self.run.skill_ids.len() {
            self.run.skill_selected = 0;
        }
    }

    pub(crate) fn refresh_logs(&mut self) {
        let dir = self.runtime_root.join("logs");
        if !dir.is_dir() {
            self.logs.missing = true;
            self.logs.error = None;
            self.logs.entries.clear();
            return;
        }
        self.logs.missing = false;
        self.logs.error = None;
        let mut files: Vec<std::path::PathBuf> = Vec::new();
        let read_dir = match fs::read_dir(&dir) {
            Ok(rd) => rd,
            Err(e) => {
                self.logs.error = Some(format!("logs read failed: {}", e));
                return;
            }
        };
        for entry in read_dir.flatten() {
            let path = entry.path();
            if path.is_file() {
                if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                    if name == "audit_rust.jsonl" {
                        continue;
                    }
                    files.push(path);
                }
            }
        }
        files.sort_by(|a, b| path_name(a).cmp(&path_name(b)));
        self.logs.entries = files;
        clamp_selection(&mut self.logs.selected, self.logs.entries.len());
    }

    pub(crate) fn refresh_process(&mut self) {
        let mut received_output = false;
        let mut drained = Vec::new();
        let mut disconnected = false;
        if let Some(rx) = self.process.receiver.as_ref() {
            loop {
                match rx.try_recv() {
                    Ok(line) => drained.push(line),
                    Err(TryRecvError::Empty) => break,
                    Err(TryRecvError::Disconnected) => {
                        disconnected = true;
                        break;
                    }
                }
            }
        }
        if disconnected {
            self.process.receiver = None;
        }
        for line in drained {
            handle_log_line(&mut self.process, line);
            received_output = true;
        }
        if received_output
            && self.active_tab == Tab::Logs
            && matches!(self.logs_focus, LogsFocus::Process)
        {
            self.logs_process_scroll = usize::MAX;
        }

        if self.process.running {
            if let Some(child) = self.process.child.as_mut() {
                match child.try_wait() {
                    Ok(Some(status)) => {
                        self.process.running = false;
                        self.process.exit_status = Some(status.code().unwrap_or(-1));
                        self.process.pid = None;
                        self.process.start_time = None;
                        self.process.child = None;
                    }
                    Ok(None) => {}
                    Err(_) => {}
                }
            } else {
                self.process.running = false;
            }
        }
    }
}
