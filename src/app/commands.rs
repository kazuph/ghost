use std::path::PathBuf;

use crate::app::{config, display, error, error::Result, helpers, process, storage};
use rusqlite::Connection;

/// Helper function to get a task by ID (supports both full UUIDs and short IDs)
fn get_task_by_id_or_short_id(conn: &Connection, task_id: &str) -> Result<storage::Task> {
    // Check if this looks like a full UUID (contains hyphens and is 36 chars)
    if task_id.len() == 36 && task_id.contains('-') {
        // Try full UUID first
        match storage::get_task(conn, task_id) {
            Ok(task) => return Ok(task),
            Err(error::GhostError::TaskNotFound { .. }) => {
                // Fall back to short ID search
            }
            Err(e) => return Err(e),
        }
    }

    // Try short ID search
    storage::get_task_by_short_id(conn, task_id)
}

/// Get the user's preferred shell from the SHELL environment variable
fn get_user_shell() -> String {
    std::env::var("SHELL").unwrap_or_else(|_| "/bin/bash".to_string())
}

/// Wrap all commands with the user's shell for consistent behavior
/// Uses login shell (-l) to load shell configuration files (.zshrc, .bashrc, etc.)
fn wrap_with_user_shell(command: Vec<String>) -> Vec<String> {
    let shell = get_user_shell();
    let command_str = command.join(" ");
    vec![shell, "-lc".to_string(), command_str]
}

/// Run a command in the background (classic wrapper that manages its own connection)
pub fn spawn(command: Vec<String>, cwd: Option<PathBuf>, env: Vec<String>) -> Result<()> {
    let conn = storage::init_database()?;
    spawn_with_conn(&conn, command, cwd, env, true, false).map(|_| ())
}

/// Run a command in the background using a shared database connection.
pub fn spawn_with_conn(
    conn: &Connection,
    command: Vec<String>,
    cwd: Option<PathBuf>,
    env: Vec<String>,
    show_output: bool,
    verify_start: bool,
) -> Result<process::ProcessInfo> {
    if command.is_empty() {
        return Err(error::GhostError::InvalidArgument {
            message: "No command specified".to_string(),
        });
    }

    // Always wrap with user's shell for consistent behavior and config loading
    let processed_command = wrap_with_user_shell(command.clone());

    let env_vars = config::env::parse_env_vars(&env)?;
    let (process_info, mut child) = spawn_and_register_process(
        command,           // Original command for database
        processed_command, // Wrapped command for execution
        cwd,
        env_vars,
        conn,
    )?;

    if verify_start {
        ensure_process_started(conn, &process_info)?;
    }

    if show_output {
        display::print_process_started(&process_info.id, process_info.pid, &process_info.log_path);
    }

    // Spawn a detached thread to reap the child once it exits so the main command can return immediately.
    std::thread::spawn(move || {
        let _ = child.wait();
    });

    Ok(process_info)
}

/// Spawn process and register it in the database
pub fn spawn_and_register_process(
    original_command: Vec<String>,
    execution_command: Vec<String>,
    cwd: Option<PathBuf>,
    env_vars: Vec<(String, String)>,
    conn: &Connection,
) -> Result<(process::ProcessInfo, std::process::Child)> {
    // If no cwd is specified, use the current directory
    let effective_cwd = match cwd {
        Some(path) => Some(path),
        None => std::env::current_dir().ok(),
    };

    let (process_info, child) = process::spawn_background_process_with_env(
        execution_command,
        effective_cwd.clone(),
        None,
        env_vars,
    )?;

    // Save to database with the actual environment variables from the process
    let env = if process_info.env.is_empty() {
        None
    } else {
        Some(process_info.env.as_slice())
    };
    storage::insert_task(
        conn,
        &process_info.id,
        process_info.pid,
        Some(process_info.pgid),
        &original_command, // Save original command, not wrapped version
        env,
        effective_cwd.as_deref(),
        &process_info.log_path,
    )?;

    Ok((process_info, child))
}

/// Convenience helper for spawning using the user's login shell wrapping strategy.
pub fn spawn_with_shell_wrapper(
    original_command: Vec<String>,
    cwd: Option<PathBuf>,
    env_vars: Vec<(String, String)>,
    conn: &Connection,
    verify_start: bool,
) -> Result<(process::ProcessInfo, std::process::Child)> {
    let execution_command = wrap_with_user_shell(original_command.clone());
    let (process_info, child) =
        spawn_and_register_process(original_command, execution_command, cwd, env_vars, conn)?;

    if verify_start {
        ensure_process_started(conn, &process_info)?;
    }

    Ok((process_info, child))
}

fn ensure_process_started(conn: &Connection, process_info: &process::ProcessInfo) -> Result<()> {
    let process_started =
        helpers::wait_for_process_start(process_info.pid, std::time::Duration::from_secs(2))?;

    if !process_started {
        storage::update_task_status(conn, &process_info.id, storage::TaskStatus::Exited, Some(1))?;
        return Err(error::GhostError::ProcessSpawn {
            message: "Process exited immediately after starting".to_string(),
        });
    }
    Ok(())
}

/// List all background processes (classic wrapper that manages its own connection)
pub fn list(status_filter: Option<String>, show_all: bool) -> Result<()> {
    let conn = storage::init_database()?;
    list_with_conn(&conn, status_filter, show_all, true).map(|_| ())
}

/// List background processes using a shared connection.
pub fn list_with_conn(
    conn: &Connection,
    status_filter: Option<String>,
    show_all: bool,
    show_output: bool,
) -> Result<Vec<storage::task::Task>> {
    let tasks = storage::get_tasks_with_process_check(conn, status_filter.as_deref(), show_all)?;

    if show_output {
        display::print_task_list(&tasks);
    }

    Ok(tasks)
}

/// Show logs for a process
pub async fn log(task_id: &str, follow: bool, all: bool, head: usize, tail: usize) -> Result<()> {
    let conn = storage::init_database()?;
    log_with_conn(&conn, task_id, follow, all, head, tail, true)
        .await
        .map(|_| ())
}

pub async fn log_with_conn(
    conn: &Connection,
    task_id: &str,
    follow: bool,
    all: bool,
    head: usize,
    tail: usize,
    show_output: bool,
) -> Result<String> {
    let task = get_task_by_id_or_short_id(conn, task_id)?;
    let log_path = PathBuf::from(&task.log_path);

    let full_content =
        std::fs::read_to_string(&log_path).map_err(|e| error::GhostError::InvalidArgument {
            message: format!("Failed to read log file: {e}"),
        })?;

    if follow {
        if show_output {
            display::print_log_follow_header(task_id, &task.log_path);
            helpers::follow_log_file(&log_path).await?;
        }
        return Ok(full_content);
    }

    let rendered_content = if all || full_content.is_empty() {
        full_content.clone()
    } else {
        let lines: Vec<&str> = full_content.lines().collect();
        let total_lines = lines.len();
        if total_lines <= head + tail {
            full_content.clone()
        } else {
            let mut buffer = String::new();
            for line in lines.iter().take(head) {
                buffer.push_str(line);
                buffer.push('\n');
            }
            if total_lines > head + tail {
                buffer.push_str(&format!(
                    "\n... {} lines omitted ...\n\n",
                    total_lines - head - tail
                ));
            }
            for line in lines.iter().skip(total_lines.saturating_sub(tail)) {
                buffer.push_str(line);
                buffer.push('\n');
            }
            buffer
        }
    };

    if show_output {
        print!("{rendered_content}");
    }

    Ok(rendered_content)
}

/// Stop a background process (classic wrapper)
pub fn stop(task_id: &str, force: bool, show_output: bool) -> Result<()> {
    let conn = storage::init_database()?;
    stop_with_conn(&conn, task_id, force, show_output)
}

pub fn stop_with_conn(
    conn: &Connection,
    task_id: &str,
    force: bool,
    show_output: bool,
) -> Result<()> {
    let task = get_task_by_id_or_short_id(conn, task_id)?;

    helpers::validate_task_running(&task)?;

    // Kill the process group if available, otherwise kill individual process
    if let Some(pgid) = task.pgid {
        process::kill_group(pgid, force)?;
    } else {
        process::kill(task.pid, force)?;
    }

    // Update status in database
    let status = if force {
        storage::TaskStatus::Killed
    } else {
        storage::TaskStatus::Exited
    };
    storage::update_task_status(conn, &task.id, status, None)?;

    if show_output {
        let pid = task.pid;
        println!("Process {task_id} ({pid}) has been {status}");
    }

    Ok(())
}

/// Restart a background process
pub fn restart(task_id: &str, force: bool) -> Result<()> {
    let conn = storage::init_database()?;
    let task = get_task_by_id_or_short_id(&conn, task_id)?;

    // Parse command, cwd, and env from task
    let command: Vec<String> =
        serde_json::from_str(&task.command).map_err(|e| error::GhostError::InvalidArgument {
            message: format!("Failed to parse command: {e}"),
        })?;
    let cwd = task.cwd.clone().map(PathBuf::from);
    let env = task
        .env
        .as_ref()
        .and_then(|e| serde_json::from_str::<std::collections::HashMap<String, String>>(e).ok())
        .map(|map| {
            map.iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    // Check if the task is still running
    let is_running = process::exists(task.pid);

    if is_running {
        // Task is running, stop it first
        println!("Stopping task {task_id}...");

        // Kill process and wait for termination
        use std::time::Duration;
        let terminated =
            helpers::kill_and_wait(task.pid, task.pgid, force, Duration::from_secs(5))?;

        if !terminated && !force {
            // If process didn't terminate with SIGTERM, try SIGKILL
            println!("Process did not terminate gracefully, forcing kill...");
            let _ = helpers::kill_and_wait(
                task.pid,
                task.pgid,
                true, // Force kill
                Duration::from_secs(2),
            );
        }

        // Update task status in database
        storage::update_task_status(&conn, &task.id, storage::TaskStatus::Killed, None)?;
    }

    // Start the task again with original working directory and environment
    println!("Starting task {task_id}...");
    match spawn_with_conn(&conn, command, cwd, env, true, true) {
        Ok(_) => {
            let action = if is_running { "restarted" } else { "rerun" };
            println!("Task {task_id} has been {action} successfully");
        }
        Err(e) => {
            return Err(error::GhostError::InvalidArgument {
                message: format!("Failed to restart task: {e}"),
            });
        }
    }

    Ok(())
}

/// Check status of a background process
pub fn status(task_id: &str) -> Result<()> {
    let conn = storage::init_database()?;
    status_with_conn(&conn, task_id, true).map(|_| ())
}

pub fn status_with_conn(
    conn: &Connection,
    task_id: &str,
    show_output: bool,
) -> Result<storage::task::Task> {
    let task = get_task_by_id_or_short_id(conn, task_id)?;
    let task = storage::update_task_status_by_process_check(conn, &task.id)?;

    if show_output {
        display::print_task_details(&task);
    }

    Ok(task)
}

/// Clean up old finished tasks
pub fn cleanup(days: u64, status: Option<String>, dry_run: bool, all: bool) -> Result<()> {
    let conn = storage::init_database()?;
    cleanup_with_conn(&conn, days, status, dry_run, all)
}

pub fn cleanup_with_conn(
    conn: &Connection,
    days: u64,
    status: Option<String>,
    dry_run: bool,
    all: bool,
) -> Result<()> {
    // Parse status filter
    let status_filter = parse_status_filter(status.as_deref())?;

    // Determine days filter - None if --all is specified
    let days_filter = if all { None } else { Some(days) };

    if dry_run {
        // Show what would be deleted
        let candidates = storage::get_cleanup_candidates(conn, days_filter, &status_filter)?;

        if candidates.is_empty() {
            println!("No tasks found matching cleanup criteria.");
            return Ok(());
        }

        println!(
            "The following {} task(s) would be deleted:",
            candidates.len()
        );
        display::print_task_list(&candidates);

        if all {
            println!(
                "\nNote: --all flag specified, all finished tasks would be deleted regardless of age."
            );
        } else {
            println!("\nNote: Only tasks older than {days} days would be deleted.");
        }
    } else {
        // Actually delete tasks
        let deleted_count = storage::cleanup_tasks_by_criteria(conn, days_filter, &status_filter)?;

        if deleted_count == 0 {
            println!("No tasks found matching cleanup criteria.");
        } else {
            println!("Successfully deleted {deleted_count} task(s).");

            if all {
                println!("Deleted all finished tasks regardless of age.");
            } else {
                println!(
                    "Deleted tasks older than {} days with status: {}.",
                    days,
                    format_status_list(&status_filter)
                );
            }
        }
    }

    Ok(())
}

/// Parse status filter string into TaskStatus enum list
fn parse_status_filter(status: Option<&str>) -> Result<Vec<storage::TaskStatus>> {
    match status {
        Some("all") => {
            // All statuses except running (don't delete running tasks)
            Ok(vec![
                storage::TaskStatus::Exited,
                storage::TaskStatus::Killed,
                storage::TaskStatus::Unknown,
            ])
        }
        Some(status_str) => {
            let statuses: Result<Vec<_>> = status_str
                .split(',')
                .map(|s| s.trim())
                .map(|s| match s {
                    "exited" => Ok(storage::TaskStatus::Exited),
                    "killed" => Ok(storage::TaskStatus::Killed),
                    "unknown" => Ok(storage::TaskStatus::Unknown),
                    "running" => Err(error::GhostError::InvalidArgument {
                        message: "Cannot cleanup running tasks".to_string(),
                    }),
                    _ => Err(error::GhostError::InvalidArgument {
                        message: format!(
                            "Invalid status: {s}. Valid options: exited, killed, unknown, all"
                        ),
                    }),
                })
                .collect();
            statuses
        }
        None => {
            // Default: exited and killed only
            Ok(vec![
                storage::TaskStatus::Exited,
                storage::TaskStatus::Killed,
            ])
        }
    }
}

/// Format status list for display
fn format_status_list(statuses: &[storage::TaskStatus]) -> String {
    statuses
        .iter()
        .map(|s| s.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

/// Start TUI mode
pub async fn tui(day_window: Option<u64>) -> Result<()> {
    use crossterm::{
        event::{DisableMouseCapture, EnableMouseCapture, Event, EventStream},
        execute,
        terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
    };
    use futures::StreamExt;
    use ratatui::{Terminal, backend::CrosstermBackend};
    use std::io;
    use tokio::time::{Duration, interval};

    use crate::app::tui::app::TuiApp;

    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Create app
    let mut app = TuiApp::new_with_day_window(day_window)?;
    app.refresh_tasks()?;

    // Setup refresh interval and event stream
    let mut refresh_interval = interval(Duration::from_secs(1));
    let mut event_stream = EventStream::new();

    let result = loop {
        // Draw the UI
        terminal.draw(|f| app.render(f))?;

        // Handle input and refresh
        tokio::select! {
            // Handle keyboard events from async stream
            Some(event_result) = event_stream.next() => {
                match event_result {
                    Ok(Event::Key(key)) => {
                        if let Err(e) = app.handle_key(key) {
                            break Err(e);
                        }
                        if app.should_quit() {
                            break Ok(());
                        }
                    }
                    Err(e) => {
                        break Err(error::GhostError::Io { source: e });
                    }
                    _ => {} // Ignore other events (Mouse, Resize, etc.)
                }
            }

            // Refresh tasks periodically
            _ = refresh_interval.tick() => {
                if let Err(e) = app.refresh_tasks() {
                    break Err(e);
                }
            }
        }
    };

    // Restore terminal
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    result
}
