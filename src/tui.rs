/// Custom TUI prompts inspired by @clack/prompts.
/// Renders ◆/●/○ style selectors with arrow key navigation.
use std::io::{self, Read, Write};

// ── Multi-Select ──────────────────────────────────────────────

pub struct MultiSelectOption {
    pub label: String,
    pub description: String,
    pub selected: bool,
}

/// Interactive multi-select with ● / ○ markers.
/// Arrow keys to move, space to toggle, enter to confirm, Ctrl+C to cancel.
/// Returns indices of selected items, or None on cancel.
pub fn multi_select(title: &str, options: &mut [MultiSelectOption]) -> Option<Vec<usize>> {
    if !std::io::IsTerminal::is_terminal(&io::stdin()) {
        // Non-interactive: return defaults
        return Some(
            options
                .iter()
                .enumerate()
                .filter(|(_, o)| o.selected)
                .map(|(i, _)| i)
                .collect(),
        );
    }

    let mut cursor: usize = 0;

    // Enter raw mode
    let fd = libc_fd();
    let old_termios = match enter_raw_mode(fd) {
        Some(t) => t,
        None => {
            // Fallback: return defaults if we can't enter raw mode
            return Some(
                options
                    .iter()
                    .enumerate()
                    .filter(|(_, o)| o.selected)
                    .map(|(i, _)| i)
                    .collect(),
            );
        }
    };

    // Initial padding for first clear
    let total_lines = options.len() + 3;
    for _ in 0..total_lines {
        eprint!("\r\n");
    }
    io::stderr().flush().ok();

    render_multi(title, options, cursor, false);

    let result = loop {
        match read_key() {
            Key::Enter => {
                if options.iter().any(|o| o.selected) {
                    render_multi(title, options, cursor, true);
                    break Some(
                        options
                            .iter()
                            .enumerate()
                            .filter(|(_, o)| o.selected)
                            .map(|(i, _)| i)
                            .collect(),
                    );
                }
                // Require at least one selection
            }
            Key::Space => {
                options[cursor].selected = !options[cursor].selected;
                render_multi(title, options, cursor, false);
            }
            Key::Up => {
                cursor = cursor.saturating_sub(1);
                render_multi(title, options, cursor, false);
            }
            Key::Down => {
                if cursor < options.len() - 1 {
                    cursor += 1;
                }
                render_multi(title, options, cursor, false);
            }
            Key::CtrlC | Key::Escape => {
                render_multi(title, options, cursor, true);
                break None;
            }
            Key::Other => {}
        }
    };

    restore_mode(fd, &old_termios);
    result
}

fn render_multi(title: &str, options: &[MultiSelectOption], cursor: usize, final_render: bool) {
    let total_lines = options.len() + 3;
    // Move up and clear
    eprint!("\x1b[{}A\x1b[J", total_lines);

    let icon = if final_render {
        "\x1b[32m◇\x1b[0m"
    } else {
        "\x1b[32m◆\x1b[0m"
    };
    eprint!("{icon}  \x1b[1m{title}\x1b[0m\r\n");

    if !final_render {
        for (i, opt) in options.iter().enumerate() {
            let check = if opt.selected {
                "\x1b[32m●\x1b[0m"
            } else {
                "\x1b[2m○\x1b[0m"
            };
            let prefix = if i == cursor {
                "\x1b[36m❯\x1b[0m"
            } else {
                " "
            };
            let label = if i == cursor {
                format!("\x1b[4m{}\x1b[0m", opt.label)
            } else {
                opt.label.clone()
            };
            let desc = &opt.description;
            eprint!("\x1b[2m│\x1b[0m {prefix} {check} {label}  \x1b[2m{desc}\x1b[0m\r\n");
        }

        eprint!("\x1b[2m│  ↑↓ move  space toggle  enter confirm\x1b[0m\r\n");

        let names: Vec<&str> = options
            .iter()
            .filter(|o| o.selected)
            .map(|o| o.label.as_str())
            .collect();
        let summary = if names.is_empty() {
            "(none)".to_string()
        } else {
            names.join(", ")
        };
        eprint!("\x1b[2m└\x1b[0m  \x1b[32mSelected:\x1b[0m {summary}\r\n");
    } else {
        let names: Vec<&str> = options
            .iter()
            .filter(|o| o.selected)
            .map(|o| o.label.as_str())
            .collect();
        eprint!("\x1b[2m│\x1b[0m  \x1b[2m{}\x1b[0m\r\n", names.join(", "));
    }

    io::stderr().flush().ok();
}

// ── Single-Select ─────────────────────────────────────────────

pub struct SelectOption {
    pub label: String,
    pub description: String,
}

/// Interactive single-select with ● / ○ markers.
/// Arrow keys to move, enter to confirm, Ctrl+C to cancel.
/// Returns index of selected item, or None on cancel.
pub fn single_select(title: &str, options: &[SelectOption], default: usize) -> Option<usize> {
    if !std::io::IsTerminal::is_terminal(&io::stdin()) {
        return Some(default);
    }

    let mut cursor = default;

    let fd = libc_fd();
    let old_termios = match enter_raw_mode(fd) {
        Some(t) => t,
        None => return Some(default),
    };

    let total_lines = options.len() + 2;
    for _ in 0..total_lines {
        eprint!("\r\n");
    }
    io::stderr().flush().ok();

    render_single(title, options, cursor, false);

    let result = loop {
        match read_key() {
            Key::Enter => {
                render_single(title, options, cursor, true);
                break Some(cursor);
            }
            Key::Up => {
                cursor = cursor.saturating_sub(1);
                render_single(title, options, cursor, false);
            }
            Key::Down => {
                if cursor < options.len() - 1 {
                    cursor += 1;
                }
                render_single(title, options, cursor, false);
            }
            Key::CtrlC | Key::Escape => {
                render_single(title, options, cursor, true);
                break None;
            }
            Key::Space | Key::Other => {}
        }
    };

    restore_mode(fd, &old_termios);
    result
}

fn render_single(title: &str, options: &[SelectOption], cursor: usize, final_render: bool) {
    let total_lines = options.len() + 2;
    eprint!("\x1b[{}A\x1b[J", total_lines);

    let icon = if final_render {
        "\x1b[32m◇\x1b[0m"
    } else {
        "\x1b[32m◆\x1b[0m"
    };
    eprint!("{icon}  \x1b[1m{title}\x1b[0m\r\n");

    if !final_render {
        for (i, opt) in options.iter().enumerate() {
            let radio = if i == cursor {
                "\x1b[32m●\x1b[0m"
            } else {
                "\x1b[2m○\x1b[0m"
            };
            let prefix = if i == cursor {
                "\x1b[36m❯\x1b[0m"
            } else {
                " "
            };
            let label = if i == cursor {
                format!("\x1b[4m{}\x1b[0m", opt.label)
            } else {
                opt.label.clone()
            };
            let desc = &opt.description;
            eprint!("\x1b[2m│\x1b[0m {prefix} {radio} {label}  \x1b[2m{desc}\x1b[0m\r\n");
        }
        eprint!("\x1b[2m└  ↑↓ move  enter confirm\x1b[0m\r\n");
    } else {
        eprint!(
            "\x1b[2m│\x1b[0m  \x1b[2m{}\x1b[0m\r\n",
            options[cursor].label
        );
    }

    io::stderr().flush().ok();
}

// ── Terminal raw mode (Unix) ──────────────────────────────────

enum Key {
    Enter,
    Space,
    Up,
    Down,
    CtrlC,
    Escape,
    Other,
}

#[cfg(unix)]
fn libc_fd() -> i32 {
    0 // stdin
}

#[cfg(not(unix))]
fn libc_fd() -> i32 {
    0
}

#[cfg(unix)]
fn enter_raw_mode(fd: i32) -> Option<libc::termios> {
    unsafe {
        let mut termios: libc::termios = std::mem::zeroed();
        if libc::tcgetattr(fd, &mut termios) != 0 {
            return None;
        }
        let old = termios;
        // Disable canonical mode and echo
        termios.c_lflag &= !(libc::ICANON | libc::ECHO);
        termios.c_cc[libc::VMIN] = 1;
        termios.c_cc[libc::VTIME] = 0;
        libc::tcsetattr(fd, libc::TCSANOW, &termios);
        Some(old)
    }
}

#[cfg(not(unix))]
fn enter_raw_mode(_fd: i32) -> Option<()> {
    None
}

#[cfg(unix)]
fn restore_mode(fd: i32, old: &libc::termios) {
    unsafe {
        libc::tcsetattr(fd, libc::TCSADRAIN, old);
    }
}

#[cfg(not(unix))]
fn restore_mode(_fd: i32, _old: &()) {}

fn read_key() -> Key {
    let mut buf = [0u8; 1];
    if io::stdin().read_exact(&mut buf).is_err() {
        return Key::Other;
    }
    match buf[0] {
        b'\r' | b'\n' => Key::Enter,
        b' ' => Key::Space,
        3 => Key::CtrlC, // Ctrl+C
        27 => {
            // Escape sequence
            let mut seq = [0u8; 2];
            if io::stdin().read_exact(&mut seq).is_err() {
                return Key::Escape;
            }
            match &seq {
                b"[A" => Key::Up,
                b"[B" => Key::Down,
                _ => Key::Other,
            }
        }
        _ => Key::Other,
    }
}
