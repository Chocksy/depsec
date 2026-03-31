use std::io::{IsTerminal, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

const FRAMES: &[&str] = &["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

pub struct Spinner {
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
    status: Arc<Mutex<String>>,
}

impl Spinner {
    /// Start a braille spinner on stderr. Only creates the thread if stderr is a terminal.
    pub fn new(message: &str) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let status = Arc::new(Mutex::new(String::new()));

        if !std::io::stderr().is_terminal() {
            return Self {
                stop,
                handle: None,
                status,
            };
        }

        // Print first frame synchronously so it appears instantly
        let cyan = "\x1b[36m";
        let dim = "\x1b[90m";
        let reset = "\x1b[0m";
        eprint!(
            "\r  {cyan}{}{reset} {message} {dim}(0s){reset}   ",
            FRAMES[0]
        );
        let _ = std::io::stderr().flush();

        let stop_clone = stop.clone();
        let status_clone = status.clone();
        let message = message.to_string();

        let handle = thread::spawn(move || {
            let start = Instant::now();
            let mut i = 1usize; // start at 1 since frame 0 was already printed

            while !stop_clone.load(Ordering::Relaxed) {
                thread::sleep(Duration::from_millis(80));

                let elapsed = start.elapsed().as_secs();
                let frame = FRAMES[i % FRAMES.len()];

                let time_str = if elapsed >= 60 {
                    let mins = elapsed / 60;
                    let secs = elapsed % 60;
                    format!("({mins}m {secs:02}s)")
                } else {
                    format!("({elapsed}s)")
                };

                let detail = status_clone.lock().map(|s| s.clone()).unwrap_or_default();
                let display = if detail.is_empty() {
                    format!("{message} {dim}{time_str}{reset}")
                } else {
                    format!("{message} {dim}{detail} {time_str}{reset}")
                };

                eprint!("\r  {cyan}{frame}{reset} {display}   ");
                let _ = std::io::stderr().flush();

                i += 1;
            }

            // Clear the spinner line
            eprint!("\r{}\r", " ".repeat(80));
            let _ = std::io::stderr().flush();
        });

        Self {
            stop,
            handle: Some(handle),
            status,
        }
    }

    /// Update the spinner's status detail (shown after the main message)
    pub fn set_status(&self, detail: &str) {
        if let Ok(mut s) = self.status.lock() {
            *s = detail.to_string();
        }
    }

    pub fn stop(mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

impl Drop for Spinner {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}
