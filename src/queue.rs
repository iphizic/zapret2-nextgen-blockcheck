use std::{collections::VecDeque, sync::Arc};
use thiserror::Error;
use tokio::sync::{Mutex, Notify};

#[derive(Debug, Error)]
pub enum QueueError {
    #[error("no queues configured")]
    EmptyPool,
}

#[derive(Clone)]
pub struct QueueAllocator {
    inner: Arc<Inner>,
}

struct Inner {
    available: Mutex<VecDeque<u16>>,
    notify: Notify,
}

impl QueueAllocator {
    pub fn new(base_qnum: u16, qnum_count: u16) -> Result<Self, QueueError> {
        if qnum_count == 0 {
            return Err(QueueError::EmptyPool);
        }
        let mut q = VecDeque::new();
        for n in 0..qnum_count {
            q.push_back(base_qnum + n);
        }
        Ok(Self {
            inner: Arc::new(Inner {
                available: Mutex::new(q),
                notify: Notify::new(),
            }),
        })
    }

    pub async fn acquire(&self) -> Result<QueueLease, QueueError> {
        loop {
            let mut guard = self.inner.available.lock().await;
            if let Some(qnum) = guard.pop_front() {
                return Ok(QueueLease {
                    qnum,
                    allocator: self.clone(),
                    released: false,
                });
            }
            drop(guard);
            self.inner.notify.notified().await;
        }
    }

    async fn release_qnum(&self, qnum: u16) {
        let mut guard = self.inner.available.lock().await;
        if !guard.contains(&qnum) {
            guard.push_back(qnum);
            self.inner.notify.notify_one();
        }
    }

    #[allow(dead_code)]
    pub async fn available_len(&self) -> usize {
        self.inner.available.lock().await.len()
    }
}

pub struct QueueLease {
    pub qnum: u16,
    allocator: QueueAllocator,
    released: bool,
}

impl QueueLease {
    pub async fn release(mut self) {
        if !self.released {
            self.allocator.release_qnum(self.qnum).await;
            self.released = true;
        }
    }
}

impl Drop for QueueLease {
    fn drop(&mut self) {
        if self.released {
            return;
        }
        let allocator = self.allocator.clone();
        let qnum = self.qnum;
        tokio::spawn(async move {
            allocator.release_qnum(qnum).await;
        });
        self.released = true;
    }
}
