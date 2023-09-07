use anyhow::{bail, Context, Result};

pub(crate) fn set_max_open_files_limit() -> Result<()> {
    let mut current_limit = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    match unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut current_limit) } {
        0 => {}
        _ => {
            bail!("Failed to get current max open files limit");
        }
    }

    println!(
        "Current max open files soft {} hard {}",
        current_limit.rlim_cur, current_limit.rlim_max
    );

    let new_limit = libc::rlimit {
        rlim_cur: current_limit.rlim_max,
        rlim_max: current_limit.rlim_max,
    };

    println!("Setting max open files soft {} hard {}", new_limit.rlim_cur, new_limit.rlim_max);

    match unsafe {
        libc::setrlimit(libc::RLIMIT_NOFILE, &new_limit)
    } {
        0 => {}
        _ => {
            bail!("Failed to set max open files limit");
        }
    }

    Ok(())
}

pub(crate) fn prepare_tokio_runtime(threads: Option<usize>) -> Result<tokio::runtime::Runtime> {
    // Using tokio we we usually need to open a lot of files. Set the max open files limit to the
    // maximum allowed by the kernel
    set_max_open_files_limit().context("Setting open file limits to max")?;

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
