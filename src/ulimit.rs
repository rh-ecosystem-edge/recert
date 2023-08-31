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
