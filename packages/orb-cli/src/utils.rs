#[macro_export]
macro_rules! fatal {
    () => {};
    ($($arg:tt)*) => {{
        eprintln!($($arg)*);
        std::process::exit(1);
    }};
}

/// Fatal error that respects silent mode - exits without printing if silent is true
#[macro_export]
macro_rules! silent_fatal {
    ($silent:expr) => {{
        std::process::exit(1);
    }};
    ($silent:expr, $($arg:tt)*) => {{
        if !$silent {
            eprintln!($($arg)*);
        }
        std::process::exit(1);
    }};
}
