use std::error::Error;
use crate::objects::common::Link;
use crate::enums::regex::{GPLINK_RE1,GPLINK_RE2};


pub fn parse_gplink(all_link: String) -> Result<Vec<Link>, Box<dyn Error>> {
   let mut gplinks: Vec<Link> = Vec::new();

   let mut cpaths: Vec<String> = Vec::new();
   for cpath in GPLINK_RE1.captures_iter(&all_link)
   {
      cpaths.push(cpath[0].to_owned());
   }

   let mut status: Vec<String> = Vec::new();
   for enforced in GPLINK_RE2.captures_iter(&all_link){
      status.push(enforced[0].to_owned());
   }

   for i in 0..cpaths.len()
   {
      let mut gplink = Link::new(false, cpaths[i].to_string());
      

      if status[i].to_string().contains(";2") | status[i].to_string().contains(";3") {
         *gplink.is_enforced_mut() = true;
      }


      gplinks.push(gplink);
   }

   Ok(gplinks)
}