use tokio::time::{timeout, Duration};
use zapret_checker::queue::QueueAllocator;

#[tokio::test]
async fn queue_allocator_unique_and_release() {
    let q = QueueAllocator::new(200, 2).unwrap();
    let a = q.acquire().await.unwrap();
    let b = q.acquire().await.unwrap();
    assert_ne!(a.qnum, b.qnum);
    assert_eq!(q.available_len().await, 0);
    let qa = a.qnum;
    a.release().await;
    assert_eq!(q.available_len().await, 1);
    let c = q.acquire().await.unwrap();
    assert_eq!(c.qnum, qa);
}

#[tokio::test]
async fn queue_allocator_waits_when_exhausted() {
    let q = QueueAllocator::new(300, 1).unwrap();
    let _lease = q.acquire().await.unwrap();
    let pending = timeout(Duration::from_millis(25), q.acquire()).await;
    assert!(pending.is_err());
}
