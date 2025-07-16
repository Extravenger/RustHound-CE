use std::collections::HashMap;
use std::error::Error;

extern crate zip;
use crate::api::ADResults;
use crate::args::Options;
use crate::utils::date::return_current_fulldate;
pub mod common;


pub fn make_result(common_args: &Options, ad_results: ADResults) -> Result<(), Box<dyn Error>> {

   let filename = common_args.domain.replace(".", "-").to_lowercase();


   let mut json_result: HashMap<String, String> = HashMap::new();


   let datetime = return_current_fulldate();


   common::add_file(
      &datetime,
      "users".to_string(),
		&filename,
      ad_results.users,
      &mut json_result,
      common_args,
   )?;
   common::add_file(
      &datetime,
      "groups".to_string(),
		&filename,
      ad_results.groups,
      &mut json_result,
      common_args,
   )?;
   common::add_file(
      &datetime,
      "computers".to_string(),
		&filename,
      ad_results.computers,
      &mut json_result,
      common_args,
   )?;
   common::add_file(
      &datetime,
      "ous".to_string(),
		&filename,
      ad_results.ous,
      &mut json_result,
      common_args,
   )?;
   common::add_file(
      &datetime,
      "domains".to_string(),
		&filename,
      ad_results.domains,
      &mut json_result,
      common_args,
   )?;
   common::add_file(
      &datetime,
      "gpos".to_string(),
      &filename,
      ad_results.gpos,
      &mut json_result,
      common_args,
   )?;

   common::add_file(
      &datetime,
      "containers".to_string(),
		&filename,
      ad_results.containers,
      &mut json_result,
      common_args,
   )?;
   common::add_file(
      &datetime,
      "ntauthstores".to_string(),
		&filename,
      ad_results.ntauthstores,
      &mut json_result,
      common_args,
   )?;
   common::add_file(
      &datetime,
      "aiacas".to_string(),
		&filename,
      ad_results.aiacas,
      &mut json_result,
      common_args,
   )?;
   common::add_file(
      &datetime,
      "rootcas".to_string(),
		&filename,
      ad_results.rootcas,
      &mut json_result,
      common_args,
   )?;
   common::add_file(
      &datetime,
      "enterprisecas".to_string(),
		&filename,
      ad_results.enterprisecas,
      &mut json_result,
      common_args,
   )?;
   common::add_file(
      &datetime,
      "certtemplates".to_string(),
		&filename,
      ad_results.certtemplates,
      &mut json_result,
      common_args,
   )?;
   common::add_file(
      &datetime,
      "issuancepolicies".to_string(),
		&filename,
      ad_results.issuancepolicies,
      &mut json_result,
      common_args,
   )?;

   if common_args.zip {
      common::make_a_zip(
         &datetime,
         &filename,
         &common_args.path,
         &json_result);
   }
   Ok(())
}