
use colored::*;
use crate::utils::date::{return_current_date,return_current_time};
use indicatif::{ProgressBar, ProgressStyle};

pub fn print_banner() {

    #[cfg(windows)]
    control::set_virtual_terminal(true).unwrap();

    println!("{}","---------------------------------------------------".clear().bold());
    println!("Initializing {} at {} on {}",
        "nonehound".truecolor(247,76,0,),
        return_current_time(),
        return_current_date()
    );
    println!("Powered By Super Mario".bold());
    println!("Thanks to ?".truecolor(153,71,146));
    println!("{}\n","---------------------------------------------------".clear().bold());
}

pub fn print_end_banner() {

    println!("\n{} Enumeration Completed at {} on {}! Happy Graphing!\n",
        "nonehound".truecolor(247,76,0,),
        return_current_time(),
        return_current_date()
    );
}

pub fn progress_bar(
	pb: ProgressBar,
	message: String,
	count: u64,
    end_message: String,
) {
	pb.set_style(ProgressStyle::with_template("{prefix:.bold.dim}{spinner} {wide_msg}")
		.unwrap()
        .tick_chars("⠁⠂⠄⡀⢀⠠⠐⠈ "));
	pb.inc(count);
	pb.with_message(format!("{}: {}{}",message,count,end_message));
}