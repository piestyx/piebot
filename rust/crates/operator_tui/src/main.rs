mod app;
mod commands;
mod config;
mod data;
mod model;
mod tabs;
mod ui;
mod widgets;

use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use model::App;
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;
use std::env;
use std::io::{self, Write};
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (runtime_root, skills_dir) = parse_args_or_prompt()?;
    let mut app = App::new(runtime_root, skills_dir);
    app.refresh_all();

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    terminal.clear()?;
    let res = app::run_app(&mut terminal, &mut app);
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    res
}

fn parse_args_or_prompt() -> Result<(PathBuf, Option<PathBuf>), Box<dyn std::error::Error>> {
    let mut args = env::args().skip(1);
    let mut runtime_arg: Option<String> = None;
    let mut skills_dir: Option<String> = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--runtime" => runtime_arg = args.next(),
            "--skills-dir" => skills_dir = args.next(),
            "--help" | "-h" => {
                println!("operator_tui --runtime <path> [--skills-dir <path>]");
                std::process::exit(0);
            }
            _ => {
                if runtime_arg.is_none() {
                    runtime_arg = Some(arg);
                }
            }
        }
    }
    let runtime_path = match runtime_arg {
        Some(arg) => arg,
        None => {
            let mut input = String::new();
            print!("Runtime path: ");
            io::stdout().flush()?;
            io::stdin().read_line(&mut input)?;
            input.trim().to_string()
        }
    };
    let runtime_root = PathBuf::from(runtime_path);
    let skills_dir = skills_dir.map(PathBuf::from);
    Ok((runtime_root, skills_dir))
}
