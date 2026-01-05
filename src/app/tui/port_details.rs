use ratatui::{
    Frame,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Wrap},
};

use crate::app::port_detector::SystemPort;

pub struct PortDetailsWidget<'a> {
    port: &'a SystemPort,
}

impl<'a> PortDetailsWidget<'a> {
    pub fn new(port: &'a SystemPort) -> Self {
        Self { port }
    }

    fn format_memory(&self) -> String {
        match self.port.memory_kb {
            None => "N/A".to_string(),
            Some(kb) => {
                if kb >= 1024 * 1024 {
                    format!("{:.1} GB ({} KB)", kb as f64 / (1024.0 * 1024.0), kb)
                } else if kb >= 1024 {
                    format!("{:.1} MB ({} KB)", kb as f64 / 1024.0, kb)
                } else {
                    format!("{} KB", kb)
                }
            }
        }
    }

    fn format_directory(&self) -> String {
        match &self.port.cwd {
            None => "N/A".to_string(),
            Some(path) => {
                // Replace home directory with ~
                if let Some(home_dir) = dirs::home_dir() {
                    if let Some(home_str) = home_dir.to_str() {
                        if path.starts_with(home_str) {
                            return path.replacen(home_str, "~", 1);
                        }
                    }
                }
                path.clone()
            }
        }
    }

    pub fn render(self, frame: &mut Frame, area: Rect) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(12), // Basic info section
                Constraint::Min(3),     // Additional info section
                Constraint::Length(2),  // Footer
            ])
            .split(area);

        // Render basic info section
        self.render_basic_info(frame, chunks[0]);

        // Render additional info section
        self.render_additional_info(frame, chunks[1]);

        // Render footer
        self.render_footer(frame, chunks[2]);
    }

    fn render_basic_info(&self, frame: &mut Frame, area: Rect) {
        let block = Block::default()
            .title(" Port Details ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan));

        // Build info lines
        let info_lines = vec![
            Line::from(vec![
                Span::styled("Port: ", Style::default().add_modifier(Modifier::BOLD)),
                Span::styled(
                    format!(":{}", self.port.port),
                    Style::default().fg(Color::Green),
                ),
                Span::raw("  "),
                Span::styled("Protocol: ", Style::default().add_modifier(Modifier::BOLD)),
                Span::raw(self.port.protocol.to_uppercase()),
            ]),
            Line::from(vec![
                Span::styled("Local Address: ", Style::default().add_modifier(Modifier::BOLD)),
                Span::raw(&self.port.local_addr),
            ]),
            Line::from(vec![
                Span::styled("PID: ", Style::default().add_modifier(Modifier::BOLD)),
                Span::raw(self.port.pid.to_string()),
                Span::raw("  "),
                Span::styled("PPID: ", Style::default().add_modifier(Modifier::BOLD)),
                Span::raw(self.port.ppid.to_string()),
            ]),
            Line::from(vec![
                Span::styled("Process: ", Style::default().add_modifier(Modifier::BOLD)),
                Span::styled(&self.port.process_name, Style::default().fg(Color::Yellow)),
            ]),
            Line::from(vec![
                Span::styled("Parent: ", Style::default().add_modifier(Modifier::BOLD)),
                Span::raw(&self.port.parent_name),
            ]),
            Line::from(vec![
                Span::styled("User: ", Style::default().add_modifier(Modifier::BOLD)),
                Span::raw(&self.port.user),
            ]),
            Line::from(vec![
                Span::styled("Memory: ", Style::default().add_modifier(Modifier::BOLD)),
                Span::raw(self.format_memory()),
            ]),
            Line::from(vec![
                Span::styled("Directory: ", Style::default().add_modifier(Modifier::BOLD)),
                Span::raw(self.format_directory()),
            ]),
        ];

        let paragraph = Paragraph::new(info_lines)
            .block(block)
            .wrap(Wrap { trim: true });

        frame.render_widget(paragraph, area);
    }

    fn render_additional_info(&self, frame: &mut Frame, area: Rect) {
        let block = Block::default()
            .title(" Process Command ")
            .borders(Borders::LEFT | Borders::RIGHT | Borders::TOP)
            .border_style(Style::default().fg(Color::Cyan));

        // Try to get the full command line from /proc or ps
        let command_line = get_process_command(self.port.pid);

        let lines = vec![Line::from(Span::raw(command_line))];

        let paragraph = Paragraph::new(lines)
            .block(block)
            .wrap(Wrap { trim: true });

        frame.render_widget(paragraph, area);
    }

    fn render_footer(&self, frame: &mut Frame, area: Rect) {
        let keybinds = vec![
            Span::styled("[j/k]", Style::default().fg(Color::Yellow)),
            Span::raw(" Navigate  "),
            Span::styled("[s]", Style::default().fg(Color::Yellow)),
            Span::raw(" Stop  "),
            Span::styled("[C-k]", Style::default().fg(Color::Yellow)),
            Span::raw(" Kill  "),
            Span::styled("[q/Esc]", Style::default().fg(Color::Yellow)),
            Span::raw(" Back"),
        ];

        let keybind_paragraph = Paragraph::new(Line::from(keybinds))
            .style(Style::default())
            .alignment(Alignment::Center)
            .block(
                Block::default()
                    .borders(Borders::LEFT | Borders::RIGHT | Borders::BOTTOM)
                    .border_style(Style::default().fg(Color::Cyan)),
            );

        frame.render_widget(keybind_paragraph, area);
    }
}

/// Get the full command line for a process
fn get_process_command(pid: u32) -> String {
    use std::process::Command;

    // Try ps command to get full command
    if let Ok(output) = Command::new("ps")
        .args(["-p", &pid.to_string(), "-o", "args="])
        .output()
    {
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let cmd = stdout.trim();
            if !cmd.is_empty() {
                return cmd.to_string();
            }
        }
    }

    "N/A".to_string()
}
