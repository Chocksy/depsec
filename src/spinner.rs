use std::io::{IsTerminal, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

const FRAMES: &[&str] = &["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

pub struct Spinner {
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl Spinner {
    /// Start a braille spinner on stderr. Only creates the thread if stderr is a terminal.
    pub fn new(message: &str) -> Self {
        let stop = Arc::new(AtomicBool::new(false));

        if !std::io::stderr().is_terminal() {
            return Self { stop, handle: None };
        }

        let stop_clone = stop.clone();
        let message = message.to_string();

        let handle = thread::spawn(move || {
            let start = Instant::now();
            let mut i = 0usize;
            let cyan = "\x1b[36m";
            let dim = "\x1b[90m";
            let reset = "\x1b[0m";

            while !stop_clone.load(Ordering::Relaxed) {
                let elapsed = start.elapsed().as_secs();
                let frame = FRAMES[i % FRAMES.len()];

                let time_str = if elapsed >= 60 {
                    let mins = elapsed / 60;
                    let secs = elapsed % 60;
                    format!("({mins}m {secs:02}s)")
                } else {
                    format!("({elapsed}s)")
                };

                eprint!("\r  {cyan}{frame}{reset} {message} {dim}{time_str}{reset}   ");
                let _ = std::io::stderr().flush();

                i += 1;
                thread::sleep(Duration::from_millis(80));
            }

            // Clear the spinner line
            eprint!("\r{}\r", " ".repeat(80));
            let _ = std::io::stderr().flush();
        });

        Self {
            stop,
            handle: Some(handle),
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
