//! Terminal User Interface (TUI) for Raijin
//! 
//! Provides a fancy CLI interface with:
//! - Left panel: Scan settings
//! - Center pane: Scrolling log output
//! - Status bar: Real-time scan statistics

use std::io::{self, Stdout};
use std::sync::mpsc::Receiver;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use std::collections::VecDeque;

use crossterm::{
    cursor::Show,
    event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem, Paragraph, Wrap},
    Frame, Terminal,
};
use crate::helpers::interrupt::ScanState;
use crate::helpers::unified_logger::{LogEvent, LogLevel, TuiMessage, EventType};
use crate::ScanConfig;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const FRAME_COLOR: Color = Color::Rgb(0x00, 0xbb, 0xde);

// --- TUI Log Entry (formatted for display) ---

#[derive(Debug, Clone)]
struct LogEntry {
    level: LogLevel,
    message: String,
    timestamp: String,
}

impl LogEntry {
    fn from_event(event: &LogEvent) -> Self {
        let timestamp = event.timestamp.format("%H:%M:%S").to_string();
        
        // Format message based on event type
        let message = match event.event_type {
            EventType::FileMatch => {
                // Format file match with path, score, and first reason
                let path = event.file_path.as_deref().unwrap_or("unknown");
                let score = event.score.unwrap_or(0.0);
                let reason = event.reasons.as_ref()
                    .and_then(|r| r.first())
                    .map(|r| r.message.as_str())
                    .unwrap_or("");
                format!("{} SCORE:{:.0} {}", path, score, reason)
            }
            EventType::ProcessMatch => {
                // Format process match with name, PID, score, and reason
                let name = event.process_name.as_deref().unwrap_or("unknown");
                let pid = event.pid.unwrap_or(0);
                let score = event.score.unwrap_or(0.0);
                let reason = event.reasons.as_ref()
                    .and_then(|r| r.first())
                    .map(|r| r.message.as_str())
                    .unwrap_or("");
                format!("{} PID:{} SCORE:{:.0} {}", name, pid, score, reason)
            }
            _ => {
                // Standard message with context
                if !event.context.is_empty() {
                    let mut msg = event.message.clone();
                    for (k, v) in &event.context {
                        msg.push_str(&format!(" {}={}", k, v));
                    }
                    msg
                } else {
                    event.message.clone()
                }
            }
        };
        
        Self {
            level: event.level,
            message,
            timestamp,
        }
    }
    
    fn level_color(&self) -> Color {
        match self.level {
            LogLevel::Alert => Color::Red,
            LogLevel::Error => Color::Magenta,
            LogLevel::Warning => Color::Yellow,
            LogLevel::Notice => Color::Cyan,
            LogLevel::Info => Color::Green,
            LogLevel::Debug => Color::DarkGray,
        }
    }
    
    fn level_str(&self) -> &'static str {
        match self.level {
            LogLevel::Alert => "ALERT",
            LogLevel::Error => "ERROR",
            LogLevel::Warning => "WARN",
            LogLevel::Notice => "NOTICE",
            LogLevel::Info => "INFO",
            LogLevel::Debug => "DEBUG",
        }
    }
}

// --- Dialog State ---

#[derive(Debug, Clone, PartialEq)]
enum DialogState {
    None,
    QuitConfirm,
}

// --- Scan Settings Display ---

struct SettingsDisplay {
    target_folder: String,
    threads: usize,
    cpu_limit: u8,
    max_file_size: String,
    scan_all_types: bool,
    scan_hard_drives: bool,
    scan_all_drives: bool,
    is_elevated: bool,
    exclusion_count: usize,
    yara_rules_count: usize,
    ioc_count: usize,
    sigma_rules_count: usize,
}

impl SettingsDisplay {
    fn from_config(config: &ScanConfig, target_folder: &str) -> Self {
        let max_file_size = if config.max_file_size >= 1_000_000 {
            format!("{:.0} MB", config.max_file_size as f64 / 1_000_000.0)
        } else if config.max_file_size >= 1_000 {
            format!("{:.0} KB", config.max_file_size as f64 / 1_000.0)
        } else {
            format!("{} B", config.max_file_size)
        };
        
        Self {
            target_folder: target_folder.to_string(),
            threads: config.threads,
            cpu_limit: config.cpu_limit,
            max_file_size,
            scan_all_types: config.scan_all_types,
            scan_hard_drives: config.scan_hard_drives,
            scan_all_drives: config.scan_all_drives,
            is_elevated: config.is_elevated,
            exclusion_count: config.exclusion_count,
            yara_rules_count: config.yara_rules_count,
            ioc_count: config.ioc_count,
            sigma_rules_count: config.sigma_rules_count,
        }
    }
    
    fn truncate_path(&self, max_len: usize) -> String {
        let char_count = self.target_folder.chars().count();
        if char_count <= max_len {
            self.target_folder.clone()
        } else {
            let keep = (max_len.saturating_sub(3)) / 2;
            if keep == 0 {
                return "...".to_string();
            }
            let start: String = self.target_folder.chars().take(keep).collect();
            let end: String = self.target_folder.chars().skip(char_count - keep).collect();
            format!("{}...{}", start, end)
        }
    }
}

// --- TUI Application State ---

pub struct TuiApp {
    logs: VecDeque<LogEntry>,
    max_logs: usize,
    scroll_offset: usize,
    auto_scroll: bool,
    last_visible_height: usize,
    dialog: DialogState,
    settings: SettingsDisplay,
    scan_state: Arc<ScanState>,
    scan_complete: bool,
    receiver: Receiver<TuiMessage>,
    // Interactive controls
    show_threads_overlay: bool,
    // Frozen duration when scan completes
    final_duration: Option<Duration>,
    // Loading state during initialization
    is_loading: bool,
    loading_message: String,
    // Spinner animation frame
    spinner_frame: usize,
}

impl TuiApp {
    pub fn new(
        config: &ScanConfig,
        target_folder: &str,
        scan_state: Arc<ScanState>,
        receiver: Receiver<TuiMessage>,
        start_loading: bool,
    ) -> Self {
        Self {
            logs: VecDeque::with_capacity(1000),
            max_logs: 1000,
            scroll_offset: 0,
            auto_scroll: true,
            last_visible_height: 20, // Will be updated on first render
            dialog: DialogState::None,
            settings: SettingsDisplay::from_config(config, target_folder),
            scan_state,
            scan_complete: false,
            receiver,
            show_threads_overlay: false,
            final_duration: None,
            is_loading: start_loading,
            loading_message: if start_loading { "Loading IOCs and signatures ...".to_string() } else { String::new() },
            spinner_frame: 0,
        }
    }
    
    fn add_log(&mut self, event: LogEvent) {
        let entry = LogEntry::from_event(&event);
        self.logs.push_back(entry);
        
        // Trim to max size
        while self.logs.len() > self.max_logs {
            self.logs.pop_front();
            // Adjust scroll offset if we removed entries
            if self.scroll_offset > 0 {
                self.scroll_offset = self.scroll_offset.saturating_sub(1);
            }
        }
        
        // Auto-scroll to bottom if enabled
        if self.auto_scroll {
            self.scroll_to_bottom();
        }
    }
    
    fn scroll_up(&mut self, amount: usize) {
        self.scroll_offset = self.scroll_offset.saturating_sub(amount);
        self.auto_scroll = false;
    }
    
    fn scroll_down(&mut self, amount: usize) {
        let max_scroll = self.logs.len().saturating_sub(self.last_visible_height);
        self.scroll_offset = (self.scroll_offset + amount).min(max_scroll);
        
        // Resume auto-scroll if at bottom
        if self.scroll_offset >= max_scroll {
            self.auto_scroll = true;
        }
    }
    
    fn scroll_to_bottom(&mut self) {
        // Will be recalculated on render
        self.scroll_offset = usize::MAX;
        self.auto_scroll = true;
    }
    
    fn scroll_to_top(&mut self) {
        self.scroll_offset = 0;
        self.auto_scroll = false;
    }
    
    fn process_messages(&mut self) {
        // Drain pending messages, but only up to a fixed number per frame so
        // a burst of findings (hundreds of thousands of Sigma hits on a big
        // EVTX) can't starve rendering and key handling. Anything left is
        // picked up on the next frame.
        const MAX_MESSAGES_PER_FRAME: usize = 2_000;
        let mut processed = 0usize;
        while processed < MAX_MESSAGES_PER_FRAME {
            let Ok(msg) = self.receiver.try_recv() else { break };
            processed += 1;
            match msg {
                TuiMessage::Log(event) => self.add_log(event),
                TuiMessage::ScanComplete => {
                    self.scan_complete = true;
                    // Freeze the timer at completion time
                    self.final_duration = Some(self.scan_state.start_time.elapsed());
                }
                TuiMessage::InitProgress(message) => {
                    self.loading_message = message;
                }
                TuiMessage::InitComplete { yara_rules_count, ioc_count, sigma_rules_count } => {
                    self.is_loading = false;
                    self.loading_message.clear();
                    // Update settings display with actual counts
                    self.settings.yara_rules_count = yara_rules_count;
                    self.settings.ioc_count = ioc_count;
                    self.settings.sigma_rules_count = sigma_rules_count;
                }
            }
        }
        
        // Advance spinner animation when loading
        if self.is_loading {
            self.spinner_frame = self.spinner_frame.wrapping_add(1);
        }
    }
    
    fn handle_key(&mut self, key: KeyCode, modifiers: KeyModifiers) -> bool {
        // Handle dialog first
        if self.dialog == DialogState::QuitConfirm {
            match key {
                KeyCode::Char('y') | KeyCode::Char('Y') => {
                    self.scan_state.should_exit.store(true, std::sync::atomic::Ordering::SeqCst);
                    return true; // Signal to exit
                }
                KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
                    self.dialog = DialogState::None;
                }
                _ => {}
            }
            return false;
        }
        
        // Handle Ctrl+C
        if modifiers.contains(KeyModifiers::CONTROL) && key == KeyCode::Char('c') {
            self.dialog = DialogState::QuitConfirm;
            return false;
        }
        
        match key {
            KeyCode::Char('q') | KeyCode::Char('Q') => {
                self.dialog = DialogState::QuitConfirm;
            }
            KeyCode::Up | KeyCode::Char('k') => {
                self.scroll_up(1);
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.scroll_down(1);
            }
            KeyCode::PageUp => {
                self.scroll_up(10);
            }
            KeyCode::PageDown => {
                self.scroll_down(10);
            }
            KeyCode::Home | KeyCode::Char('g') => {
                self.scroll_to_top();
            }
            KeyCode::End | KeyCode::Char('G') => {
                self.scroll_to_bottom();
            }
            KeyCode::Esc => {
                // Close overlay if open, otherwise resume auto-scroll
                if self.show_threads_overlay {
                    self.show_threads_overlay = false;
                } else {
                    self.scroll_to_bottom();
                }
            }
            // --- Interactive Controls ---
            KeyCode::Char('-') | KeyCode::Char('_') => {
                // Decrease CPU limit by 10%
                let new_limit = self.scan_state.adjust_cpu_limit(-10);
                self.settings.cpu_limit = new_limit;
            }
            KeyCode::Char('+') | KeyCode::Char('=') => {
                // Increase CPU limit by 10%
                let new_limit = self.scan_state.adjust_cpu_limit(10);
                self.settings.cpu_limit = new_limit;
            }
            KeyCode::Char('p') | KeyCode::Char('P') => {
                // Toggle pause
                self.scan_state.toggle_pause();
            }
            KeyCode::Char('s') | KeyCode::Char('S') => {
                // Skip all current elements
                self.scan_state.request_skip();
            }
            KeyCode::Char('t') | KeyCode::Char('T') => {
                // Toggle thread activity overlay
                self.show_threads_overlay = !self.show_threads_overlay;
            }
            _ => {}
        }
        
        false
    }
}

// --- TUI Rendering ---

/// Below this width the 24-column settings panel costs more than it shows:
/// the braille logo gets sliced mid-glyph and the log pane is squeezed to a
/// few unreadable columns. Drop the panel and give the whole width to the logs
/// instead (the same information is in the console banner).
const MIN_WIDTH_FOR_SETTINGS_PANEL: u16 = 72;

fn render_ui(frame: &mut Frame, app: &mut TuiApp) {
    let size = frame.area();
    
    // Main layout: horizontal split for settings | logs
    let content_area = if size.width >= MIN_WIDTH_FOR_SETTINGS_PANEL {
        let main_chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Length(24),  // Settings panel width
                Constraint::Min(40),     // Log panel (rest)
            ])
            .split(size);
        
        // Left panel: Settings
        render_settings_panel(frame, app, main_chunks[0]);
        main_chunks[1]
    } else {
        size
    };
    
    // Right side: vertical split for logs | status bar
    let right_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(5),      // Log panel
            Constraint::Length(3),   // Status bar
        ])
        .split(content_area);
    
    // Logs panel
    render_logs_panel(frame, app, right_chunks[0]);
    
    // Status bar
    render_status_bar(frame, app, right_chunks[1]);
    
    // Render overlays (in order of priority)
    if app.show_threads_overlay {
        render_threads_overlay(frame, app, size);
    }
    
    // Render loading overlay during initialization (high priority)
    if app.is_loading {
        render_loading_overlay(frame, app, size);
    }
    
    // Render dialog if active (highest priority)
    if app.dialog == DialogState::QuitConfirm {
        render_quit_dialog(frame, size);
    }
}

fn render_settings_panel(frame: &mut Frame, app: &TuiApp, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(FRAME_COLOR))
        .style(Style::default().bg(Color::Black));
    
    let inner = block.inner(area);
    frame.render_widget(block, area);
    
    let max_path_len = (inner.width as usize).saturating_sub(2);
    let target = app.settings.truncate_path(max_path_len);
    
    // Raijin ASCII Logo
    let logo_style = Style::default().fg(Color::Green);

    let settings_text = vec![
        // ASCII Logo (braille skull) - the panel is 24 columns wide, so the
        // wordmark lives in the console banner, not here.
        Line::from(Span::styled("⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣀⣤⣤⣤⣤⡤⣤⣀⠀⠀⠀⠀", logo_style)),
        Line::from(Span::styled("⠀⠀⠀⠀⠀⣠⣴⠒⣿⣿⣯⣿⡼⠏⣻⣷⣬⣿⣶⡄⠀⠀", logo_style)),
        Line::from(Span::styled("⠀⠀⠀⣠⣾⣻⣼⣿⣿⠿⠿⠿⠇⢸⣿⡏⣩⣭⠉⠻⠀⠀", logo_style)),
        Line::from(Span::styled("⠀⠀⢸⣿⣽⣿⣿⠛⠁⠀⠀⠀⠀⠈⠻⡇⠻⣾⠳⡄⠀⠀", logo_style)),
        Line::from(Span::styled("⠀⢀⣿⣶⣿⣿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠈⠀⢹⣏⣳⠀⠀", logo_style)),
        Line::from(Span::styled("⠀⢸⡟⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣼⡇⠀", logo_style)),
        Line::from(Span::styled("⠀⠸⣯⣿⣿⣇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⢾⡇⠀", logo_style)),
        Line::from(Span::styled("⠀⠀⢹⡼⢿⣿⣧⡀⠀⠀⠀⠀⠀⠀⠀⠀⣰⣿⡛⡿⠀⠀", logo_style)),
        Line::from(Span::styled("⠀⠀⠀⠻⣟⣻⣿⣿⣦⣤⣀⣀⣀⣠⣴⣿⢿⣭⡿⠃⠀⠀", logo_style)),
        Line::from(Span::styled("⠀⠀⠀⠀⠈⠳⢾⣏⡿⢿⡿⣿⢿⣿⣿⣽⠿⠟⠀⠀⠀⠀", logo_style)),
        Line::from(Span::styled("⠀⠀⠀⠀⠀⠀⠈⠙⠛⠒⠛⠒⠛⠋⠁⠀⠀⠀⠀⠀⠀⠀", logo_style)),
        Line::from(""),
        // Version and copyright (centered)
        Line::from(Span::styled(format!(" RAIJIN v{}", VERSION), Style::default().fg(Color::White).add_modifier(Modifier::BOLD))),
        Line::from(Span::styled(" (c) TCS-CERT", Style::default().fg(Color::DarkGray))),
        Line::from(""),
        // Settings header
        Line::from(Span::styled(" SCAN SETTINGS", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD))),
        Line::from(""),
        Line::from(vec![
            Span::styled(" Target:", Style::default().fg(Color::Cyan)),
        ]),
        Line::from(vec![
            Span::styled(format!(" {}", target), Style::default().fg(Color::White)),
        ]),
        Line::from(vec![
            Span::styled(" Elevated: ", Style::default().fg(Color::Cyan)),
            Span::styled(
                if app.settings.is_elevated { "Yes" } else { "No" },
                Style::default().fg(if app.settings.is_elevated { Color::Green } else { Color::Yellow }),
            ),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled(" YARA Rules: ", Style::default().fg(Color::Cyan)),
            Span::styled(app.settings.yara_rules_count.to_string(), Style::default().fg(Color::White)),
        ]),
        Line::from(vec![
            Span::styled(" Sigma Rules: ", Style::default().fg(Color::Cyan)),
            Span::styled(app.settings.sigma_rules_count.to_string(), Style::default().fg(Color::White)),
        ]),
        Line::from(vec![
            Span::styled(" IOCs: ", Style::default().fg(Color::Cyan)),
            Span::styled(app.settings.ioc_count.to_string(), Style::default().fg(Color::White)),
        ]),
        Line::from(vec![
            Span::styled(" Exclusions: ", Style::default().fg(Color::Cyan)),
            Span::styled(app.settings.exclusion_count.to_string(), Style::default().fg(Color::White)),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled(" Threads: ", Style::default().fg(Color::Cyan)),
            Span::styled(app.settings.threads.to_string(), Style::default().fg(Color::White)),
        ]),
        Line::from(vec![
            Span::styled(" CPU Limit: ", Style::default().fg(Color::Cyan)),
            Span::styled(format!("{}%", app.settings.cpu_limit), Style::default().fg(Color::White)),
        ]),
        Line::from(vec![
            Span::styled(" File Size: ", Style::default().fg(Color::Cyan)),
            Span::styled(&app.settings.max_file_size, Style::default().fg(Color::White)),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled(" All Types: ", Style::default().fg(Color::Cyan)),
            Span::styled(
                if app.settings.scan_all_types { "Yes" } else { "No" },
                Style::default().fg(if app.settings.scan_all_types { Color::Green } else { Color::DarkGray }),
            ),
        ]),
        Line::from(vec![
            Span::styled(" Hard Drives: ", Style::default().fg(Color::Cyan)),
            Span::styled(
                if app.settings.scan_hard_drives { "Yes" } else { "No" },
                Style::default().fg(if app.settings.scan_hard_drives { Color::Green } else { Color::DarkGray }),
            ),
        ]),
        Line::from(vec![
            Span::styled(" All Drives: ", Style::default().fg(Color::Cyan)),
            Span::styled(
                if app.settings.scan_all_drives { "Yes" } else { "No" },
                Style::default().fg(if app.settings.scan_all_drives { Color::Green } else { Color::DarkGray }),
            ),
        ]),
        Line::from(vec![
            Span::styled(" Skipped: ", Style::default().fg(Color::Cyan)),
            Span::styled(
                format!("{}", app.scan_state.skipped.load(std::sync::atomic::Ordering::Relaxed)),
                Style::default().fg(Color::DarkGray)
            ),
        ]),
    ];

    let paragraph = Paragraph::new(settings_text)
        .style(Style::default().bg(Color::Black));
    
    frame.render_widget(paragraph, inner);
}

fn render_logs_panel(frame: &mut Frame, app: &mut TuiApp, area: Rect) {
    let scroll_indicator = if app.auto_scroll {
        "AUTO"
    } else {
        "PAUSED"
    };
    
    let scroll_style = if app.auto_scroll {
        Style::default().fg(Color::Green)
    } else {
        Style::default().fg(Color::Yellow)
    };
    
    let title = Line::from(vec![
        Span::styled(" LOG OUTPUT ", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
        Span::styled(format!("[{}] ", scroll_indicator), scroll_style),
    ]);
    
    let block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(Style::default().fg(FRAME_COLOR))
        .style(Style::default().bg(Color::Black));
    
    let inner = block.inner(area);
    frame.render_widget(block, area);
    
    let visible_height = inner.height as usize;
    let total_logs = app.logs.len();
    
    // Store visible height for scroll calculations
    app.last_visible_height = visible_height;
    
    // Calculate proper scroll offset
    let max_scroll = total_logs.saturating_sub(visible_height);
    if app.scroll_offset > max_scroll {
        app.scroll_offset = max_scroll;
    }
    
    // Re-enable auto-scroll if we're at the bottom
    if app.scroll_offset >= max_scroll && !app.auto_scroll {
        app.auto_scroll = true;
    }
    
    // Create list items for visible logs
    let items: Vec<ListItem> = app.logs
        .iter()
        .skip(app.scroll_offset)
        .take(visible_height)
        .map(|entry| {
            let level_span = Span::styled(
                format!("[{} ]", entry.level_str()),
                Style::default()
                    .fg(entry.level_color())
                    .add_modifier(if entry.level == LogLevel::Alert { Modifier::BOLD } else { Modifier::empty() }),
            );
            
            let time_span = Span::styled(
                format!(" {} ", entry.timestamp),
                Style::default().fg(Color::DarkGray),
            );
            
            // Truncate message to fit (UTF-8 safe)
            let max_msg_len = (inner.width as usize).saturating_sub(18);
            let char_count = entry.message.chars().count();
            let msg = if char_count > max_msg_len {
                let truncate_at = max_msg_len.saturating_sub(3);
                format!("{}...", entry.message.chars().take(truncate_at).collect::<String>())
            } else {
                entry.message.clone()
            };
            
            let msg_span = Span::styled(msg, Style::default().fg(Color::White));
            
            ListItem::new(Line::from(vec![level_span, time_span, msg_span]))
        })
        .collect();
    
    let list = List::new(items)
        .style(Style::default().bg(Color::Black));
    
    frame.render_widget(list, inner);
}

fn render_status_bar(frame: &mut Frame, app: &TuiApp, area: Rect) {
    // Every walked filesystem entry (files *and* directories), not just the
    // ones that actually got read and passed to YARA - a live progress
    // counter, not the final "Files scanned" count in the scan summary
    // (which only counts files that survived extension/type/size/exclusion
    // filtering and were actually content-scanned). Labeled "Entries" below
    // specifically to avoid conflating the two.
    let files = app.scan_state.files_scanned.load(std::sync::atomic::Ordering::Relaxed);
    let procs = app.scan_state.processes_scanned.load(std::sync::atomic::Ordering::Relaxed);
    let events = app.scan_state.sigma_events_scanned.load(std::sync::atomic::Ordering::Relaxed);
    let alerts = app.scan_state.alerts.load(std::sync::atomic::Ordering::Relaxed);
    let warnings = app.scan_state.warnings.load(std::sync::atomic::Ordering::Relaxed);
    let notices = app.scan_state.notices.load(std::sync::atomic::Ordering::Relaxed);

    // Get dynamic CPU limit from ScanState
    let current_cpu_limit = app.scan_state.get_cpu_limit();
    let is_paused = app.scan_state.is_scan_paused();

    // Use frozen duration if scan is complete, otherwise show live elapsed time
    let duration = app.final_duration.unwrap_or_else(|| app.scan_state.start_time.elapsed());
    let hours = duration.as_secs() / 3600;
    let mins = (duration.as_secs() % 3600) / 60;
    let secs = duration.as_secs() % 60;

    let dark = Style::default().fg(Color::DarkGray);
    let cyan = Style::default().fg(Color::Cyan);
    let white = Style::default().fg(Color::White);

    let state_style = if app.scan_complete {
        Style::default().fg(Color::Black).bg(Color::Green).add_modifier(Modifier::BOLD)
    } else if is_paused {
        Style::default().fg(Color::Black).bg(Color::Yellow).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::Green)
    };
    let (state_long, state_short) = if app.scan_complete {
        (" [DONE - press q to exit] ", " [DONE] ")
    } else if is_paused {
        (" [PAUSED] ", " [PAUSED] ")
    } else {
        (" [RUN] ", " [RUN] ")
    };

    // The status bar is one line inside a bordered box, so whatever runs past
    // the right border is silently clipped - which is how Events, the timer
    // and the key hints used to vanish on an 80-column terminal without a
    // trace. Build it as priority-tagged segments instead and drop the least
    // useful ones until the line fits. Priority 0 never gets dropped; higher
    // numbers go first.
    let mut segments: Vec<(u8, Vec<Span>)> = vec![
        (2, vec![
            Span::styled("Entries: ", cyan),
            Span::styled(format_number(files), white),
        ]),
        (4, vec![
            Span::styled(" | Procs: ", cyan),
            Span::styled(format_number(procs), white),
        ]),
        (3, vec![
            Span::styled(" | Events: ", cyan),
            Span::styled(format_number(events), white),
        ]),
        (1, vec![
            Span::styled(" | ", dark),
            Span::styled("A:", Style::default().fg(Color::Red)),
            Span::styled(alerts.to_string(), Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
            Span::styled(" W:", Style::default().fg(Color::Yellow)),
            Span::styled(warnings.to_string(), Style::default().fg(Color::Yellow)),
            Span::styled(" N:", cyan),
            Span::styled(notices.to_string(), cyan),
        ]),
        (5, vec![
            Span::styled(" | ", dark),
            Span::styled(format!("{:02}:{:02}:{:02}", hours, mins, secs), Style::default().fg(Color::Green)),
        ]),
        (6, vec![
            Span::styled(" | ", dark),
            Span::styled(format!("CPU:{}% ", current_cpu_limit), white),
            Span::styled("[+/-]", dark),
        ]),
        (7, vec![
            Span::styled(" | ", dark),
            Span::styled("[p]ause [s]kip [t]hreads [q]uit", dark),
        ]),
    ];

    let inner_width = area.width.saturating_sub(2) as usize;
    let seg_width = |spans: &Vec<Span>| spans.iter().map(|s| s.width()).sum::<usize>();
    let mut state_label = state_long;
    let mut used: usize = state_label.len() + segments.iter().map(|(_, s)| seg_width(s)).sum::<usize>();

    // Shed the statistics first and the "press q to exit" wording only once
    // there is nothing else left to give up: on a finished scan that label is
    // the one thing on screen telling the operator how to get their shell
    // back, so it outranks the counters it is competing with.
    while used > inner_width {
        if let Some(idx) = segments
            .iter()
            .enumerate()
            .filter(|(_, (priority, _))| *priority > 0)
            .max_by_key(|(_, (priority, _))| *priority)
            .map(|(i, _)| i)
        {
            used -= seg_width(&segments[idx].1);
            segments.remove(idx);
        } else if state_label != state_short {
            used = used - state_label.len() + state_short.len();
            state_label = state_short;
        } else {
            break;
        }
    }

    // Dropping the leading counters can leave the first survivor starting with
    // its own " | ", dangling right after the state label.
    if let Some((_, first)) = segments.first_mut() {
        if let Some(span) = first.first_mut() {
            if let Some(rest) = span.content.strip_prefix(" | ") {
                let (rest, style) = (rest.to_string(), span.style);
                if rest.is_empty() {
                    first.remove(0);
                } else {
                    *span = Span::styled(rest, style);
                }
            }
        }
    }

    let mut spans = vec![Span::styled(state_label, state_style)];
    for (_, segment) in segments {
        spans.extend(segment);
    }

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(FRAME_COLOR))
        .style(Style::default().bg(Color::Black));

    let paragraph = Paragraph::new(vec![Line::from(spans)])
        .block(block)
        .wrap(Wrap { trim: true });

    frame.render_widget(paragraph, area);
}

/// Center a `width` x `height` box inside `area`, clamped to it.
///
/// Overlays used to build their Rect from a fixed size and clamp only the
/// origin, so on a terminal narrower or shorter than the overlay the Rect ran
/// past the frame buffer and ratatui panicked with "index outside of buffer".
/// That panic killed the TUI thread mid-frame while the scan kept running, so
/// the terminal was left frozen on the last drawn frame - still in raw mode,
/// still on the alternate screen, with no hint of what happened.
fn centered_overlay(area: Rect, width: u16, height: u16) -> Rect {
    let width = width.min(area.width);
    let height = height.min(area.height);
    Rect::new(
        area.x + (area.width - width) / 2,
        area.y + (area.height - height) / 2,
        width,
        height,
    )
}

fn render_quit_dialog(frame: &mut Frame, area: Rect) {
    // Center the dialog
    let dialog_area = centered_overlay(area, 40, 5);
    
    // Clear the area behind the dialog first (important for proper overlay)
    frame.render_widget(Clear, dialog_area);
    
    let block = Block::default()
        .title(Span::styled(
            " QUIT SCAN? ",
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Red))
        .style(Style::default().bg(Color::Black));
    
    let text = vec![
        Line::from(""),
        Line::from(vec![
            Span::styled("  Press ", Style::default().fg(Color::White)),
            Span::styled("[Y]", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
            Span::styled(" to quit, ", Style::default().fg(Color::White)),
            Span::styled("[N]", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
            Span::styled(" to cancel", Style::default().fg(Color::White)),
        ]),
    ];
    
    let paragraph = Paragraph::new(text)
        .block(block);
    
    frame.render_widget(paragraph, dialog_area);
}

fn render_loading_overlay(frame: &mut Frame, app: &TuiApp, area: Rect) {
    // Spinner characters for animation
    const SPINNER: &[char] = &['|', '/', '-', '\\'];
    let spinner_char = SPINNER[app.spinner_frame % SPINNER.len()];
    
    // Center the loading overlay
    let overlay_area = centered_overlay(area, 50, 7);
    
    // Clear the area behind the overlay
    frame.render_widget(Clear, overlay_area);
    
    let block = Block::default()
        .title(Span::styled(
            " INITIALIZING ",
            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan))
        .style(Style::default().bg(Color::Black));
    
    let text = vec![
        Line::from(""),
        Line::from(vec![
            Span::styled(format!("  {} ", spinner_char), Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
            Span::styled(&app.loading_message, Style::default().fg(Color::White)),
        ]),
        Line::from(""),
        Line::from(Span::styled("  Please wait...", Style::default().fg(Color::DarkGray))),
    ];
    
    let paragraph = Paragraph::new(text)
        .block(block);
    
    frame.render_widget(paragraph, overlay_area);
}

fn render_threads_overlay(frame: &mut Frame, app: &TuiApp, area: Rect) {
    // Collect current elements from all threads
    let mut entries: Vec<_> = app.scan_state.current_elements.iter()
        .map(|r| (*r.key(), r.value().clone()))
        .collect();
    entries.sort_by_key(|k| k.0);
    
    let active_threads = entries.len();
    let is_paused = app.scan_state.is_scan_paused();
    
    // Calculate overlay size (centered, 80% width, dynamic height based on thread count)
    // Height: entries + empty line + shortcuts + 2 borders = entries + 4
    let overlay_width = (area.width as f32 * 0.8).min(100.0) as u16;
    let overlay_height = (entries.len() as u16 + 4).max(8);
    let overlay_area = centered_overlay(area, overlay_width, overlay_height);
    
    // Clear the area behind the overlay first (important for proper overlay)
    frame.render_widget(Clear, overlay_area);
    
    // Build title with status
    let title_status = if is_paused {
        Span::styled(" [PAUSED] ", Style::default().fg(Color::Black).bg(Color::Yellow).add_modifier(Modifier::BOLD))
    } else {
        Span::styled(" [SCANNING] ", Style::default().fg(Color::Black).bg(Color::Green).add_modifier(Modifier::BOLD))
    };
    
    let title = Line::from(vec![
        Span::styled(" THREAD ACTIVITY ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        title_status,
        Span::styled(format!(" ({} active) ", active_threads), Style::default().fg(Color::White)),
    ]);
    
    let block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan))
        .style(Style::default().bg(Color::Black));
    
    let inner = block.inner(overlay_area);
    frame.render_widget(block, overlay_area);
    
    // Create list items for each thread
    let max_path_len = (inner.width as usize).saturating_sub(12);
    
    let items: Vec<ListItem> = if entries.is_empty() {
        vec![
            ListItem::new(Line::from(vec![
                Span::styled("  ", Style::default()),
                Span::styled(
                    if is_paused { "Scan is paused. Press [p] to resume." } else { "(No active scans)" },
                    Style::default().fg(Color::DarkGray).add_modifier(Modifier::ITALIC)
                ),
            ])),
        ]
    } else {
        entries.iter().map(|(thread_id, element)| {
            let truncated = truncate_path(element, max_path_len);
            ListItem::new(Line::from(vec![
                Span::styled(format!(" [{:2}] ", thread_id + 1), Style::default().fg(Color::Yellow)),
                Span::styled(truncated, Style::default().fg(Color::White)),
            ]))
        }).collect()
    };
    
    // Add help text at bottom
    let mut all_items = items;
    all_items.push(ListItem::new(Line::from("")));
    all_items.push(ListItem::new(Line::from(vec![
        Span::styled(" ", Style::default()),
        Span::styled("[s]", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
        Span::styled(" skip all  ", Style::default().fg(Color::DarkGray)),
        Span::styled("[p]", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
        Span::styled(" pause/resume  ", Style::default().fg(Color::DarkGray)),
        Span::styled("[Esc/t]", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
        Span::styled(" close", Style::default().fg(Color::DarkGray)),
    ])));
    
    let list = List::new(all_items)
        .style(Style::default().bg(Color::Black));
    
    frame.render_widget(list, inner);
}

/// Truncate path from the middle for display (UTF-8 safe)
fn truncate_path(path: &str, max_len: usize) -> String {
    let char_count = path.chars().count();
    if char_count <= max_len {
        path.to_string()
    } else {
        let keep = (max_len.saturating_sub(3)) / 2;
        if keep == 0 {
            "...".to_string()
        } else {
            let start: String = path.chars().take(keep).collect();
            let end: String = path.chars().skip(char_count - keep).collect();
            format!("{}...{}", start, end)
        }
    }
}

fn format_number(n: usize) -> String {
    let s = n.to_string();
    let bytes = s.as_bytes();
    let len = bytes.len();
    let mut result = String::with_capacity(len + (len - 1) / 3);
    
    for (i, b) in bytes.iter().enumerate() {
        result.push(*b as char);
        if (len - i - 1) % 3 == 0 && i != len - 1 {
            result.push(',');
        }
    }
    result
}

// --- TUI Runner ---

// --- Terminal Ownership ---

/// Set while the TUI holds the terminal (raw mode + alternate screen).
static TUI_ACTIVE: AtomicBool = AtomicBool::new(false);

/// Hand the terminal back to the shell: leave the alternate screen, drop raw
/// mode, show the cursor again.
///
/// Every path that can end the process while the TUI is up has to come through
/// here first - a fatal initialization error, a panic on a scan thread, the
/// normal exit. Skipping it leaves the shell staring at the last rendered
/// frame with raw mode still on and the cursor hidden, which reads as a frozen
/// terminal (and hides whatever error message caused the exit).
///
/// Safe to call from anywhere and any number of times: only the call that
/// flips the flag back to false does the work.
pub fn restore_terminal() {
    if !TUI_ACTIVE.swap(false, Ordering::SeqCst) {
        return;
    }
    let _ = disable_raw_mode();
    let _ = execute!(io::stdout(), LeaveAlternateScreen, Show);
}

/// Restore the terminal before the default panic handler prints its message,
/// so the backtrace lands on the real screen instead of the alternate one.
fn install_panic_hook() {
    static INSTALLED: AtomicBool = AtomicBool::new(false);
    if INSTALLED.swap(true, Ordering::SeqCst) {
        return;
    }
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        restore_terminal();
        previous(info);
    }));
}

pub fn run_tui(
    config: &ScanConfig,
    target_folder: &str,
    scan_state: Arc<ScanState>,
    receiver: Receiver<TuiMessage>,
    start_loading: bool,
) -> io::Result<()> {
    // Setup terminal
    install_panic_hook();
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    TUI_ACTIVE.store(true, Ordering::SeqCst);
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    
    // Create app state
    let mut app = TuiApp::new(config, target_folder, scan_state.clone(), receiver, start_loading);
    
    // Main loop - returns (user_quit, scan_was_complete)
    let (user_quit, scan_complete) = run_main_loop(&mut terminal, &mut app);
    
    // Restore terminal
    restore_terminal();
    
    // If user quit while scan was still running, force exit the whole process
    // This ensures background scan threads are terminated
    if user_quit && !scan_complete {
        std::process::exit(130); // 130 = 128 + SIGINT (2)
    }
    
    Ok(())
}

/// Returns (user_quit, scan_was_complete)
/// - user_quit: true if user explicitly pressed q+Y, false otherwise
/// - scan_was_complete: true if scan had finished before exit
fn run_main_loop(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    app: &mut TuiApp,
) -> (bool, bool) {
    loop {
        // Process any pending messages
        app.process_messages();
        
        // Draw UI
        if terminal.draw(|f| render_ui(f, app)).is_err() {
            return (false, app.scan_complete); // Terminal error
        }
        
        // Poll for events with timeout
        if let Ok(true) = event::poll(Duration::from_millis(50)) {
            if let Ok(Event::Key(key)) = event::read() {
                // Only handle Press events (Windows sends both Press and Release)
                if key.kind == KeyEventKind::Press {
                    if app.handle_key(key.code, key.modifiers) {
                        return (true, app.scan_complete); // User confirmed quit
                    }
                }
            }
        }
    }
}
