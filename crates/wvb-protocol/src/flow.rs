#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowError {
    Exhausted,
    Overflow,
    InvalidUpdate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CreditWindow {
    available: u64,
    maximum: u64,
}

impl CreditWindow {
    #[must_use]
    pub const fn new(initial: u64, maximum: u64) -> Option<Self> {
        if initial > maximum {
            return None;
        }
        Some(Self {
            available: initial,
            maximum,
        })
    }

    #[must_use]
    pub const fn available(self) -> u64 {
        self.available
    }

    pub fn debit(&mut self, bytes: u64) -> Result<(), FlowError> {
        if bytes > self.available {
            return Err(FlowError::Exhausted);
        }
        self.available -= bytes;
        Ok(())
    }

    pub fn replenish(&mut self, bytes: u64) -> Result<(), FlowError> {
        if bytes == 0 || bytes > 16 * 1024 * 1024 {
            return Err(FlowError::InvalidUpdate);
        }
        self.available = self
            .available
            .checked_add(bytes)
            .ok_or(FlowError::Overflow)?;
        if self.available > self.maximum {
            return Err(FlowError::Overflow);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credit_never_underflows_or_overflows() {
        let mut window = CreditWindow::new(100, 200).unwrap();
        window.debit(100).unwrap();
        assert_eq!(window.debit(1), Err(FlowError::Exhausted));
        window.replenish(200).unwrap();
        assert_eq!(window.replenish(1), Err(FlowError::Overflow));
        assert_eq!(window.replenish(0), Err(FlowError::InvalidUpdate));
    }
}
