use anyhow::{Context, Result};

pub(crate) fn set_max_open_files_limit() {
    let mut current_limit = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    unsafe {
        libc::getrlimit(libc::RLIMIT_NOFILE, &mut current_limit);
    }

    let new_limit = libc::rlimit {
        rlim_cur: current_limit.rlim_max,
        rlim_max: current_limit.rlim_max,
    };

    unsafe {
        libc::setrlimit(libc::RLIMIT_NOFILE, &new_limit);
    }
}

pub(crate) fn prepare_tokio_runtime(threads: Option<usize>) -> Result<tokio::runtime::Runtime> {
    // Using tokio we we usually need to open a lot of files. Set the max open files limit to the
    // maximum allowed by the kernel
    set_max_open_files_limit();

    Ok(if let Some(threads) = threads {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(threads)
            .enable_all()
            .build()
            .context("building tokio runtime")?
    } else {
        tokio::runtime::Runtime::new()?
    })
}

