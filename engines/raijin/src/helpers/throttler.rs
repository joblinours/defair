use std::time::{Duration, Instant};
use std::thread;
use std::cell::RefCell;

thread_local! {
    pub static THROTTLER: RefCell<CpuThrottler> = RefCell::new(CpuThrottler::new(100));
}

pub struct CpuThrottler {
    target_percent: u8,
    work_start: Option<Instant>,
    accumulated_work_ns: u64,
    last_throttle_check: Instant,
}

impl CpuThrottler {
    pub fn new(target_percent: u8) -> Self {
        let percent = target_percent.clamp(1, 100);
        Self {
            target_percent: percent,
            work_start: None,
            accumulated_work_ns: 0,
            last_throttle_check: Instant::now(),
        }
    }

    pub fn set_target(&mut self, target_percent: u8) {
        self.target_percent = target_percent.clamp(1, 100);
    }

    pub fn start_work(&mut self) {
        // Always record start time - the target check happens in end_work_and_throttle()
        // This allows dynamic CPU limit adjustments to take effect immediately
        self.work_start = Some(Instant::now());
    }

    pub fn end_work_and_throttle(&mut self) {
        if self.target_percent >= 100 {
            return;
        }

        if let Some(start) = self.work_start.take() {
            let work_duration = start.elapsed();
            self.accumulated_work_ns += work_duration.as_nanos() as u64;

            let min_batch_ns: u64 = 10_000_000;
            if self.accumulated_work_ns >= min_batch_ns {
                let sleep_ns = self.calculate_sleep_ns(self.accumulated_work_ns);
                if sleep_ns > 0 {
                    thread::sleep(Duration::from_nanos(sleep_ns));
                }
                self.accumulated_work_ns = 0;
                self.last_throttle_check = Instant::now();
            }
        }
    }

    fn calculate_sleep_ns(&self, work_ns: u64) -> u64 {
        if self.target_percent >= 100 || self.target_percent == 0 {
            return 0;
        }
        let target = self.target_percent as u64;
        (work_ns * (100 - target)) / target
    }
}

#[allow(dead_code)]
pub fn init_thread_throttler(target_percent: u8) {
    THROTTLER.with(|t| {
        t.borrow_mut().set_target(target_percent);
    });
}

pub fn throttle_start() {
    THROTTLER.with(|t| {
        t.borrow_mut().start_work();
    });
}

#[allow(dead_code)]
pub fn throttle_end() {
    THROTTLER.with(|t| {
        t.borrow_mut().end_work_and_throttle();
    });
}

/// End work and throttle with a dynamically provided CPU limit
/// This allows the limit to be adjusted during runtime from ScanState
pub fn throttle_end_with_limit(cpu_limit: u8) {
    THROTTLER.with(|t| {
        let mut throttler = t.borrow_mut();
        throttler.set_target(cpu_limit);
        throttler.end_work_and_throttle();
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn test_throttler_creation_default() {
        let throttler = CpuThrottler::new(100);
        assert_eq!(throttler.target_percent, 100);
    }

    #[test]
    fn test_throttler_creation_clamped_high() {
        let throttler = CpuThrottler::new(150);
        assert_eq!(throttler.target_percent, 100);
    }

    #[test]
    fn test_throttler_creation_clamped_low() {
        let throttler = CpuThrottler::new(0);
        assert_eq!(throttler.target_percent, 1);
    }

    #[test]
    fn test_throttler_set_target() {
        let mut throttler = CpuThrottler::new(100);
        throttler.set_target(50);
        assert_eq!(throttler.target_percent, 50);
    }

    #[test]
    fn test_throttler_set_target_clamped() {
        let mut throttler = CpuThrottler::new(100);
        throttler.set_target(0);
        assert_eq!(throttler.target_percent, 1);
        throttler.set_target(200);
        assert_eq!(throttler.target_percent, 100);
    }

    #[test]
    fn test_throttler_100_percent_no_sleep() {
        let mut throttler = CpuThrottler::new(100);
        let start = Instant::now();
        throttler.start_work();
        std::thread::sleep(Duration::from_millis(1));
        throttler.end_work_and_throttle();
        assert!(start.elapsed().as_millis() < 50);
    }

    #[test]
    fn test_calculate_sleep_ns_50_percent() {
        let throttler = CpuThrottler::new(50);
        let sleep_ns = throttler.calculate_sleep_ns(10_000_000);
        assert_eq!(sleep_ns, 10_000_000);
    }

    #[test]
    fn test_calculate_sleep_ns_100_percent() {
        let throttler = CpuThrottler::new(100);
        let sleep_ns = throttler.calculate_sleep_ns(10_000_000);
        assert_eq!(sleep_ns, 0);
    }

    #[test]
    fn test_thread_local_functions() {
        init_thread_throttler(50);
        THROTTLER.with(|t| {
            assert_eq!(t.borrow().target_percent, 50);
        });

        throttle_start();
        THROTTLER.with(|t| {
            assert!(t.borrow().work_start.is_some());
        });
    }

    // =========================================================================
    // Additional Resource Constraint Tests (Module 6 extension)
    // =========================================================================

    #[test]
    fn test_calculate_sleep_ns_25_percent() {
        let throttler = CpuThrottler::new(25);
        let sleep_ns = throttler.calculate_sleep_ns(10_000_000);
        // At 25% target: sleep = work * (100-25)/25 = work * 75/25 = work * 3
        assert_eq!(sleep_ns, 30_000_000);
    }

    #[test]
    fn test_calculate_sleep_ns_75_percent() {
        let throttler = CpuThrottler::new(75);
        let sleep_ns = throttler.calculate_sleep_ns(30_000_000);
        // At 75% target: sleep = work * (100-75)/75 = work * 25/75 = work * 1/3
        assert_eq!(sleep_ns, 10_000_000);
    }

    #[test]
    fn test_calculate_sleep_ns_1_percent() {
        let throttler = CpuThrottler::new(1);
        let sleep_ns = throttler.calculate_sleep_ns(1_000_000);
        // At 1% target: sleep = work * (100-1)/1 = work * 99
        assert_eq!(sleep_ns, 99_000_000);
    }

    #[test]
    fn test_100_percent_does_no_sleeping() {
        let mut throttler = CpuThrottler::new(100);
        
        // Record start time
        let start = Instant::now();
        
        // Simulate work
        throttler.start_work();
        // Do some minimal work
        let _ = (0..1000).sum::<i32>();
        throttler.end_work_and_throttle();
        
        // Should complete almost immediately (no sleep at 100%)
        let elapsed = start.elapsed();
        assert!(elapsed.as_millis() < 50, "100% should not sleep, took {}ms", elapsed.as_millis());
    }

    #[test]
    fn test_very_low_target_calculates_large_sleep() {
        // Test that 1% target results in sleeping 99x the work time
        let throttler = CpuThrottler::new(1);
        
        // 10ms of work
        let work_ns: u64 = 10_000_000;
        let sleep_ns = throttler.calculate_sleep_ns(work_ns);
        
        // At 1%, sleep should be 99x work = 990ms
        assert_eq!(sleep_ns, 990_000_000);
        
        // Verify the ratio
        let ratio = sleep_ns as f64 / work_ns as f64;
        assert!((ratio - 99.0).abs() < 0.001, "Sleep ratio should be 99x at 1% target");
    }

    #[test]
    fn test_target_percent_values() {
        // Test boundary values
        let cases = vec![
            (1, 1),    // Minimum
            (50, 50),  // Middle
            (100, 100), // Maximum
        ];

        for (input, expected) in cases {
            let throttler = CpuThrottler::new(input);
            assert_eq!(throttler.target_percent, expected);
        }
    }

    #[test]
    fn test_zero_work_ns() {
        let throttler = CpuThrottler::new(50);
        let sleep_ns = throttler.calculate_sleep_ns(0);
        assert_eq!(sleep_ns, 0, "Zero work should result in zero sleep");
    }

    #[test]
    fn test_accumulated_work_below_threshold() {
        // Test that small work chunks don't trigger immediate sleeping
        let mut throttler = CpuThrottler::new(50);
        
        // Record initial accumulated work
        let initial_accumulated = throttler.accumulated_work_ns;
        
        throttler.start_work();
        // Very short "work" - below the 10ms batch threshold
        throttler.end_work_and_throttle();
        
        // Work should be accumulated but not necessarily trigger sleep yet
        // (depends on actual elapsed time being below min_batch_ns)
        // Just verify no panic and state is valid
        assert!(throttler.accumulated_work_ns >= initial_accumulated);
    }

    #[test]
    fn test_dynamic_target_adjustment() {
        let mut throttler = CpuThrottler::new(100);
        assert_eq!(throttler.target_percent, 100);

        // Dynamically reduce to 50%
        throttler.set_target(50);
        assert_eq!(throttler.target_percent, 50);

        // Sleep calculation should now reflect new target
        let sleep_ns = throttler.calculate_sleep_ns(10_000_000);
        assert_eq!(sleep_ns, 10_000_000); // 50% = equal work and sleep
    }

    #[test]
    fn test_throttle_end_with_limit() {
        // Test the throttle_end_with_limit function
        init_thread_throttler(100);
        
        throttle_start();
        throttle_end_with_limit(50);
        
        // Verify the target was updated
        THROTTLER.with(|t| {
            assert_eq!(t.borrow().target_percent, 50);
        });
    }
}
