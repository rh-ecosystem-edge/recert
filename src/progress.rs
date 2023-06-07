// use indicatif::ProgressStyle;

// use indicatif::ProgressBar;

// pub(crate) fn create_progress_bar(message: &str, len: usize) -> ProgressBar {
//     let progress = ProgressBar::new(len as u64).with_message(message.to_string().clone());
//     style_progress(&progress);
//     progress
// }

// fn style_progress(progress: &ProgressBar) {
//     progress.set_style(
//         ProgressStyle::default_bar()
//             .template("[{elapsed_precise}] {bar:40.cyan/blue} {pos:>7}/{len:7} {msg}")
//             .unwrap()
//             .progress_chars("##-"),
//     );
// }
