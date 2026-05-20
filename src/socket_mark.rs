use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SoMarkError {
    #[error("SO_MARK is only supported on Linux")]
    UnsupportedPlatform,
    #[error("failed to set SO_MARK: {0}")]
    SetFailed(String),
}

pub trait SocketMarkSetter {
    fn set_mark(&self, mark: u32) -> Result<(), SoMarkError>;
}

#[cfg(target_os = "linux")]
mod linux {
    use super::{SoMarkError, SocketMarkSetter};
    use std::os::unix::io::AsRawFd;

    pub fn set_socket_mark(raw_fd: i32, mark: u32) -> Result<(), SoMarkError> {
        let mark_u32 = mark;
        let result = unsafe {
            libc::setsockopt(
                raw_fd,
                libc::SOL_SOCKET,
                libc::SO_MARK,
                &mark_u32 as *const u32 as *const libc::c_void,
                std::mem::size_of::<u32>() as libc::socklen_t,
            )
        };
        if result == 0 {
            Ok(())
        } else {
            Err(SoMarkError::SetFailed(
                std::io::Error::last_os_error().to_string(),
            ))
        }
    }

    impl SocketMarkSetter for socket2::Socket {
        fn set_mark(&self, mark: u32) -> Result<(), SoMarkError> {
            set_socket_mark(self.as_raw_fd(), mark)
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod linux {
    use super::{SoMarkError, SocketMarkSetter};

    pub fn set_socket_mark(_raw_fd: i32, _mark: u32) -> Result<(), SoMarkError> {
        Err(SoMarkError::UnsupportedPlatform)
    }

    impl SocketMarkSetter for socket2::Socket {
        fn set_mark(&self, _mark: u32) -> Result<(), SoMarkError> {
            Err(SoMarkError::UnsupportedPlatform)
        }
    }
}

pub use linux::set_socket_mark;

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    struct FakeSocket {
        requested_mark: Cell<Option<u32>>,
        supported: bool,
    }

    impl SocketMarkSetter for FakeSocket {
        fn set_mark(&self, mark: u32) -> Result<(), SoMarkError> {
            if !self.supported {
                return Err(SoMarkError::UnsupportedPlatform);
            }
            self.requested_mark.set(Some(mark));
            Ok(())
        }
    }

    #[test]
    fn socket_mark_abstraction_reports_unsupported_platform() {
        let socket = FakeSocket {
            requested_mark: Cell::new(None),
            supported: false,
        };
        assert_eq!(
            socket.set_mark(0x20000001),
            Err(SoMarkError::UnsupportedPlatform)
        );
    }

    #[test]
    fn socket_mark_abstraction_accepts_mark_on_supported_backend() {
        let socket = FakeSocket {
            requested_mark: Cell::new(None),
            supported: true,
        };
        assert!(socket.set_mark(0x20000001).is_ok());
        assert_eq!(socket.requested_mark.get(), Some(0x20000001));
    }
}
