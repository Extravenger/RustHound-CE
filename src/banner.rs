
use colored::*;
use crate::utils::date::{return_current_date,return_current_time};
use indicatif::{ProgressBar, ProgressStyle};


pub fn print_banner() {

    #[cfg(windows)]
    control::set_virtual_terminal(true).unwrap();


    println!("{}","---------------------------------------------------".clear().bold());
    println!("Initializing {} at {} on {}",
        "RustHound-CE".truecolor(247,76,0,),
        return_current_time(),
        return_current_date()
    );
    println!("Powered by {}","@g0h4n_0".bold());
    println!("{}\n","---------------------------------------------------".clear().bold());
}


pub fn print_end_banner() {

    println!("\n{} Enumeration Completed at {} on {}! Happy Graphing!\n",
        "RustHound-CE".truecolor(247,76,0,),
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