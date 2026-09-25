use super::pipeline_entities::OutputTail;
use std::collections::VecDeque;

#[derive(Debug, Clone)]
pub struct BoundedOutputBuffer {
    head: Vec<u8>,
    head_cap: usize,
    tail: VecDeque<u8>,
    tail_cap: usize,
    total_bytes: usize,
    dropped_bytes: usize,
}

impl BoundedOutputBuffer {
    pub fn new(head_cap: usize, tail_cap: usize) -> Self {
        Self {
            head: Vec::with_capacity(head_cap.min(64 * 1024)),
            head_cap,
            tail: VecDeque::with_capacity(tail_cap.min(64 * 1024)),
            tail_cap,
            total_bytes: 0,
            dropped_bytes: 0,
        }
    }

    pub fn write(&mut self, chunk: &[u8]) {
        self.total_bytes += chunk.len();

        let mut offset = 0;
        // 1. Fill head buffer if not full
        if self.head.len() < self.head_cap {
            let available = self.head_cap - self.head.len();
            let to_copy = available.min(chunk.len());
            self.head.extend_from_slice(&chunk[..to_copy]);
            offset += to_copy;
        }

        // 2. Feed remaining into tail ring buffer
        if offset < chunk.len() {
            let remainder = &chunk[offset..];
            for &b in remainder {
                if self.tail.len() >= self.tail_cap {
                    self.tail.pop_front();
                    self.dropped_bytes += 1;
                }
                self.tail.push_back(b);
            }
        }
    }

    pub fn get_tail(&self, max_bytes: usize) -> OutputTail {
        let head_str = String::from_utf8_lossy(&self.head).to_string();

        let tail_slice: Vec<u8> = if self.tail.len() > max_bytes {
            let start = self.tail.len() - max_bytes;
            self.tail.iter().skip(start).copied().collect()
        } else {
            self.tail.iter().copied().collect()
        };
        let tail_str = String::from_utf8_lossy(&tail_slice).to_string();

        OutputTail {
            head: head_str,
            tail: tail_str,
            dropped_bytes: self.dropped_bytes,
            total_bytes: self.total_bytes,
        }
    }

    pub fn total_bytes(&self) -> usize {
        self.total_bytes
    }

    pub fn dropped_bytes(&self) -> usize {
        self.dropped_bytes
    }

    pub fn is_empty(&self) -> bool {
        self.total_bytes == 0
    }
}

impl Default for BoundedOutputBuffer {
    fn default() -> Self {
        // Default 2MB Head / 8MB Tail = 10MB cap total as per Contract A
        Self::new(2 * 1024 * 1024, 8 * 1024 * 1024)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_buffer_no_overflow() {
        let mut buf = BoundedOutputBuffer::new(10, 10);
        buf.write(b"hello");
        assert_eq!(buf.total_bytes(), 5);
        assert_eq!(buf.dropped_bytes(), 0);

        let tail = buf.get_tail(100);
        assert_eq!(tail.head, "hello");
        assert_eq!(tail.tail, "");
        assert_eq!(tail.dropped_bytes, 0);
    }

    #[test]
    fn test_buffer_spill_to_tail() {
        let mut buf = BoundedOutputBuffer::new(5, 5);
        buf.write(b"hello_world"); // len 11
        assert_eq!(buf.total_bytes(), 11);
        // Head gets "hello" (5 bytes)
        // Tail gets remainder: "_world" (6 bytes), but cap is 5, so 1 dropped ('_'), tail has "world"
        assert_eq!(buf.dropped_bytes(), 1);

        let tail = buf.get_tail(10);
        assert_eq!(tail.head, "hello");
        assert_eq!(tail.tail, "world");
        assert_eq!(tail.dropped_bytes, 1);
        assert_eq!(tail.total_bytes, 11);
    }

    #[test]
    fn test_buffer_large_truncation() {
        let mut buf = BoundedOutputBuffer::new(4, 4);
        buf.write(b"HEAD123456789TAIL");
        let tail = buf.get_tail(4);
        assert_eq!(tail.head, "HEAD");
        assert_eq!(tail.tail, "TAIL");
        assert!(tail.dropped_bytes > 0);
    }
}
