use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub struct RateLimiter {
    locked_map: Mutex<HashMap<String, Instant>>,
    cleanup_last: Mutex<Instant>,
    cleanup_delay: Duration,
    timeout: Duration,
}

impl RateLimiter {
    pub fn new(timeout_secs: u64) -> Self {
        RateLimiter {
            locked_map: Mutex::new(HashMap::new()),
            timeout: Duration::from_secs(timeout_secs),
            cleanup_last: Mutex::new(Instant::now()),
            cleanup_delay: Duration::from_secs(timeout_secs * 10),
        }
    }

    pub fn action_perform(&self, identifier: String) -> bool {
        self.maybe_cleanup();

        let mut locked_map = self.locked_map.lock().unwrap();
        let action_ok = locked_map
            .get(&identifier)
            .map(|instant| instant.elapsed())
            .map(|duration| duration >= self.timeout)
            .unwrap_or(true);
        if action_ok {
            locked_map.insert(identifier, Instant::now());
        }
        action_ok
    }

    pub fn action_check(&self, identifier: String) -> bool {
        let locked_map = self.locked_map.lock().unwrap();
        locked_map
            .get(&identifier)
            .map(|instant| instant.elapsed())
            .map(|duration| duration >= self.timeout)
            .unwrap_or(true)
    }

    fn maybe_cleanup(&self) {
        let mut cleanup_last = self.cleanup_last.lock().unwrap();
        if cleanup_last.elapsed() > self.cleanup_delay {
            return;
        }
        *cleanup_last = Instant::now();

        let mut locked_map = self.locked_map.lock().unwrap();
        locked_map.retain(|_, instant| instant.elapsed() < self.timeout);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::thread;

    #[test]
    fn perform_check_immediate() {
        let rate_limiter = RateLimiter::new(1);

        assert!(rate_limiter.action_perform("action".to_owned()));

        assert!(!rate_limiter.action_perform("action".to_owned()));
    }

    #[test]
    fn perform_check_after_timeout() {
        let rate_limiter = RateLimiter::new(1);

        assert!(rate_limiter.action_perform("action".to_owned()));
        thread::sleep(Duration::from_secs(1));

        assert!(rate_limiter.action_perform("action".to_owned()));
    }
}
