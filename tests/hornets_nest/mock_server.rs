use std::io::Read;
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

/// A mock TCP server that records incoming connections and data.
/// Used by protect-tier tests to verify exfiltration attempts.
pub struct MockTcpServer {
    port: u16,
    received: Arc<Mutex<Vec<Vec<u8>>>>,
    shutdown: Arc<Mutex<bool>>,
    handle: Option<JoinHandle<()>>,
}

impl MockTcpServer {
    /// Start a mock TCP server on a random available port
    pub fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("Failed to bind mock server");
        let port = listener.local_addr().unwrap().port();
        listener
            .set_nonblocking(true)
            .expect("Failed to set non-blocking");

        let received = Arc::new(Mutex::new(Vec::new()));
        let shutdown = Arc::new(Mutex::new(false));

        let recv_clone = Arc::clone(&received);
        let shutdown_clone = Arc::clone(&shutdown);

        let handle = thread::spawn(move || loop {
            if *shutdown_clone.lock().unwrap() {
                break;
            }

            match listener.accept() {
                Ok((mut stream, _)) => {
                    if *shutdown_clone.lock().unwrap() {
                        break;
                    }
                    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                    let mut buf = Vec::new();
                    let _ = stream.read_to_end(&mut buf);
                    recv_clone.lock().unwrap().push(buf);
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(_) => break,
            }
        });

        Self {
            port,
            received,
            shutdown,
            handle: Some(handle),
        }
    }

    #[allow(dead_code)]
    pub fn port(&self) -> u16 {
        self.port
    }

    #[allow(dead_code)]
    pub fn has_connections(&self) -> bool {
        !self.received.lock().unwrap().is_empty()
    }

    #[allow(dead_code)]
    pub fn received_data(&self) -> Vec<Vec<u8>> {
        self.received.lock().unwrap().clone()
    }
}

impl Drop for MockTcpServer {
    fn drop(&mut self) {
        *self.shutdown.lock().unwrap() = true;
        let _ = TcpStream::connect(format!("127.0.0.1:{}", self.port));
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_mock_server_receives_data() {
        let server = MockTcpServer::start();
        let port = server.port();

        let mut stream = TcpStream::connect(format!("127.0.0.1:{}", port)).unwrap();
        stream.write_all(b"stolen-credentials").unwrap();
        drop(stream);

        // Poll until data arrives (10ms accept loop + 2s read timeout)
        for _ in 0..50 {
            thread::sleep(Duration::from_millis(100));
            if !server.received_data().is_empty()
                && server.received_data()[0].starts_with(b"stolen")
            {
                break;
            }
        }

        assert!(
            server.has_connections(),
            "Server should have received a connection"
        );
    }
}
