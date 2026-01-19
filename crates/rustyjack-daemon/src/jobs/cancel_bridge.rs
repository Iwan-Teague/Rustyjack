// Helper to bridge tokio CancellationToken to std::sync::atomic::AtomicBool
// This allows passing cancellation to non-async code.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

/// Create an AtomicBool flag that gets set when the CancellationToken is cancelled.
///
/// This spawns a background task that waits for cancellation and sets the flag.
/// The flag can be passed to blocking/synchronous code that needs cancellation support.
pub fn create_cancel_flag(token: &CancellationToken) -> Arc<AtomicBool> {
    let flag = Arc::new(AtomicBool::new(false));
    let flag_clone = flag.clone();
    let token_clone = token.clone();
    
    // Spawn task to monitor cancellation
    tokio::spawn(async move {
        token_clone.cancelled().await;
        flag_clone.store(true, Ordering::Relaxed);
    });
    
    flag
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn test_cancel_flag_not_cancelled() {
        let token = CancellationToken::new();
        let flag = create_cancel_flag(&token);
        
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert!(!flag.load(Ordering::Relaxed));
    }

    #[tokio::test]
    async fn test_cancel_flag_cancelled() {
        let token = CancellationToken::new();
        let flag = create_cancel_flag(&token);
        
        token.cancel();
        tokio::time::sleep(Duration::from_millis(10)).await;
        
        assert!(flag.load(Ordering::Relaxed));
    }

    #[tokio::test]
    async fn test_cancel_flag_immediate() {
        let token = CancellationToken::new();
        token.cancel();
        
        let flag = create_cancel_flag(&token);
        tokio::time::sleep(Duration::from_millis(10)).await;
        
        assert!(flag.load(Ordering::Relaxed));
    }
}
