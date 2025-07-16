
pub mod resolver;

use std::collections::HashMap;
use std::error::Error;

use crate::args::Options;
use crate::objects::computer::Computer;


pub async fn run_modules(
   common_args:   &Options, 
   fqdn_ip:       &mut HashMap<String, String>, 
   vec_computers: &mut Vec<Computer>,
) -> Result<(), Box<dyn Error>> {

   if common_args.fqdn_resolver {
      resolver::resolv::resolving_all_fqdn(
         common_args.dns_tcp,
         &common_args.name_server,
         fqdn_ip,
         &vec_computers
      ).await;
   }

   Ok(())
}