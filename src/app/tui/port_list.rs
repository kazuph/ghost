use ratatui::{
    layout::{Constraint, Rect},
    style::{Color, Style},
    widgets::{Block, Borders, Cell, Row, StatefulWidget, Table, TableState, Widget},
};

use super::table_state_scroll::TableScroll;
use crate::app::port_detector::SystemPort;

// Layout constants for port list
const PORT_COLUMN_WIDTH: u16 = 7;
const PROTOCOL_COLUMN_WIDTH: u16 = 6;
const PID_COLUMN_WIDTH: u16 = 7;
const USER_COLUMN_WIDTH: u16 = 10;
const MEMORY_COLUMN_WIDTH: u16 = 8;
const PROCESS_COLUMN_WIDTH: u16 = 14;
const PARENT_COLUMN_WIDTH: u16 = 12;
const DIRECTORY_COLUMN_MIN_WIDTH: u16 = 15;

const COLUMN_CONSTRAINTS: [Constraint; 8] = [
    Constraint::Length(PORT_COLUMN_WIDTH),
    Constraint::Length(PROTOCOL_COLUMN_WIDTH),
    Constraint::Length(PID_COLUMN_WIDTH),
    Constraint::Length(USER_COLUMN_WIDTH),
    Constraint::Length(MEMORY_COLUMN_WIDTH),
    Constraint::Length(PROCESS_COLUMN_WIDTH),
    Constraint::Length(PARENT_COLUMN_WIDTH),
    Constraint::Min(DIRECTORY_COLUMN_MIN_WIDTH),
];

pub struct SystemPortListWidget<'a> {
    ports: Vec<SystemPort>,
    table_scroll: &'a mut TableScroll,
    is_active: bool,
}

impl<'a> SystemPortListWidget<'a> {
    pub fn new(
        ports: Vec<SystemPort>,
        table_scroll: &'a mut TableScroll,
        is_active: bool,
    ) -> Self {
        Self {
            ports,
            table_scroll,
            is_active,
        }
    }

    fn create_header_row(&self) -> Row<'static> {
        Row::new(vec![
            Cell::from(" Port"),
            Cell::from(" Proto"),
            Cell::from(" PID"),
            Cell::from(" User"),
            Cell::from(" Memory"),
            Cell::from(" Process"),
            Cell::from(" Parent"),
            Cell::from(" Directory"),
        ])
        .style(Style::default())
    }

    fn format_directory(&self, path: Option<&String>) -> String {
        match path {
            None => "-".to_string(),
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

    fn format_memory(&self, memory_kb: Option<u64>) -> String {
        match memory_kb {
            None => "-".to_string(),
            Some(kb) => {
                if kb >= 1024 * 1024 {
                    format!("{:.1}G", kb as f64 / (1024.0 * 1024.0))
                } else if kb >= 1024 {
                    format!("{:.1}M", kb as f64 / 1024.0)
                } else {
                    format!("{kb}K")
                }
            }
        }
    }
}

impl<'a> Widget for SystemPortListWidget<'a> {
    fn render(self, area: Rect, buf: &mut ratatui::buffer::Buffer) {
        let port_count = self.ports.len();
        let title = format!(" External Ports ({port_count} ports) ");

        // Border color based on active state
        let border_color = if self.is_active {
            Color::Cyan
        } else {
            Color::DarkGray
        };

        let block = Block::default()
            .borders(Borders::ALL)
            .title(title)
            .border_style(Style::default().fg(border_color));

        let inner_area = block.inner(area);
        ratatui::widgets::Widget::render(block, area, buf);

        // Calculate content height (subtract footer space)
        let content_height = inner_area.height.saturating_sub(2);

        // Render table content
        self.render_table_content(
            Rect {
                x: inner_area.x,
                y: inner_area.y,
                width: inner_area.width,
                height: content_height,
            },
            buf,
        );

        // Render footer
        if inner_area.height >= 2 {
            let footer_y = inner_area.y + inner_area.height - 1;
            let separator_y = footer_y - 1;
            if separator_y >= inner_area.y {
                self.render_footer_separator(inner_area.x, separator_y, inner_area.width, buf, border_color);
            }
            self.render_footer_text(inner_area.x, footer_y, inner_area.width, buf);
        }
    }
}

impl<'a> SystemPortListWidget<'a> {
    fn render_table_content(&self, area: Rect, buf: &mut ratatui::buffer::Buffer) {
        if self.ports.is_empty() {
            // Empty state
            let rows = vec![
                Row::new(vec![
                    Cell::from(""),
                    Cell::from(""),
                    Cell::from(""),
                    Cell::from(""),
                    Cell::from(""),
                    Cell::from(""),
                    Cell::from(""),
                    Cell::from(""),
                ]),
                Row::new(vec![
                    Cell::from(""),
                    Cell::from(" No external listening ports"),
                    Cell::from(""),
                    Cell::from(""),
                    Cell::from(""),
                    Cell::from(""),
                    Cell::from(""),
                    Cell::from(""),
                ]),
            ];

            let table = Table::new(rows, COLUMN_CONSTRAINTS).header(self.create_header_row());
            ratatui::widgets::Widget::render(table, area, buf);
        } else {
            let rows: Vec<Row> = self
                .ports
                .iter()
                .map(|port| {
                    let directory = self.format_directory(port.cwd.as_ref());
                    let memory = self.format_memory(port.memory_kb);

                    Row::new(vec![
                        Cell::from(format!(" :{}", port.port)),
                        Cell::from(format!(" {}", port.protocol)),
                        Cell::from(format!(" {}", port.pid)),
                        Cell::from(format!(" {}", truncate_string(&port.user, USER_COLUMN_WIDTH as usize - 1))),
                        Cell::from(format!(" {memory}")),
                        Cell::from(format!(" {}", truncate_string(&port.process_name, PROCESS_COLUMN_WIDTH as usize - 1))),
                        Cell::from(format!(" {}", truncate_string(&port.parent_name, PARENT_COLUMN_WIDTH as usize - 1))),
                        Cell::from(format!(" {directory}")),
                    ])
                })
                .collect();

            // Only show highlight if active
            let table = if self.is_active {
                Table::new(rows, COLUMN_CONSTRAINTS)
                    .header(self.create_header_row())
                    .row_highlight_style(Style::default().bg(Color::DarkGray))
            } else {
                Table::new(rows, COLUMN_CONSTRAINTS)
                    .header(self.create_header_row())
            };

            let mut table_state = TableState::default();
            if self.is_active {
                table_state.select(self.table_scroll.selected());
            }
            StatefulWidget::render(table, area, buf, &mut table_state);
        }
    }

    fn render_footer_separator(
        &self,
        x: u16,
        y: u16,
        width: u16,
        buf: &mut ratatui::buffer::Buffer,
        border_color: Color,
    ) {
        buf[(x - 1, y)].set_symbol("├");
        for i in 0..width {
            buf[(x + i, y)]
                .set_symbol("─")
                .set_style(Style::default().fg(border_color));
        }
        buf[(x + width, y)].set_symbol("┤");
    }

    fn render_footer_text(&self, x: u16, y: u16, width: u16, buf: &mut ratatui::buffer::Buffer) {
        let keybinds_text = if self.is_active {
            " j/k:Move  Enter/d:Details  Tab:Switch Panel  q:Quit"
        } else {
            " Tab:Switch to this panel"
        };

        for (i, ch) in keybinds_text.chars().enumerate() {
            let pos_x = x + i as u16;
            if pos_x < x + width {
                buf[(pos_x, y)].set_symbol(&ch.to_string());
            }
        }

        let text_len = keybinds_text.chars().count() as u16;
        for i in text_len..width {
            buf[(x + i, y)].set_symbol(" ");
        }
    }
}

/// Truncate string to fit within max_len, adding "…" if truncated
fn truncate_string(s: &str, max_len: usize) -> String {
    if s.chars().count() <= max_len {
        s.to_string()
    } else if max_len > 1 {
        format!("{}…", s.chars().take(max_len - 1).collect::<String>())
    } else {
        "…".to_string()
    }
}
