use serde_json::value::Value;
use serde::{Deserialize, Serialize};
use ldap3::SearchEntry;
use log::{debug, trace};
use std::collections::HashMap;
use std::error::Error;

use crate::enums::regex::OBJECT_SID_RE1;
use crate::objects::common::{LdapObject, AceTemplate, SPNTarget, Link, Member};
use crate::utils::date::string_to_epoch;
use crate::enums::secdesc::LdapSid;
use crate::enums::sid::{objectsid_to_vec8, sid_maker};


#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct Fsp {
    #[serde(rename = "Properties")]
    properties: FspProperties,
    #[serde(rename = "Aces")]
    aces: Vec<AceTemplate>,
    #[serde(rename = "ObjectIdentifier")]
    object_identifier: String,
    #[serde(rename = "IsDeleted")]
    is_deleted: bool,
    #[serde(rename = "IsACLProtected")]
    is_acl_protected: bool,
    #[serde(rename = "ContainedBy")]
    contained_by: Option<Member>,
}

impl Fsp {

    pub fn new() -> Self { 
        Self { ..Default::default() } 
    }


    pub fn parse(
        &mut self,
        result: SearchEntry,
        domain: &str,
        dn_sid: &mut HashMap<String, String>,
        sid_type: &mut HashMap<String, String>,
    ) -> Result<(), Box<dyn Error>> {
        let result_dn: String = result.dn.to_uppercase();
        let result_attrs: HashMap<String, Vec<String>> = result.attrs;
        let result_bin: HashMap<String, Vec<Vec<u8>>> = result.bin_attrs;


        debug!("Parse ForeignSecurityPrincipal: {result_dn}");


        for (key, value) in &result_attrs {
            trace!("  {key:?}:{value:?}");
        }

        for (key, value) in &result_bin {
            trace!("  {key:?}:{value:?}");
        }


        self.properties.domain = domain.to_uppercase();
        self.properties.distinguishedname = result_dn;    

        #[allow(unused_assignments)]
        let mut sid: String = "".to_owned();
        let mut ftype: &str = "Base";


        for (key, value) in &result_attrs {
            match key.as_str() {
                "name" => {
                    let name = format!("{}-{}", domain, &value.first().unwrap_or(&"".to_owned()));
                    self.properties.name = name.to_uppercase();



                    let split = value[0].split("-").collect::<Vec<&str>>();



                    if split.len() >= 17 {
                        ftype = "User";
                    } else {
                        ftype = "Group";
                    }
                }
                "whenCreated" => {
                    let epoch = string_to_epoch(&value[0])?;
                    if epoch.is_positive() {
                        self.properties.whencreated = epoch;
                    }
                }
                "objectSid" => {

                    let vec_sid = objectsid_to_vec8(&value[0]);
                    sid = sid_maker(LdapSid::parse(&vec_sid).unwrap().1, domain);
                    self.object_identifier = sid.to_owned();

                    for domain_sid in OBJECT_SID_RE1.captures_iter(&sid) {
                        self.properties.domainsid = domain_sid[0].to_owned().to_string();
                    }
                }
                "IsDeleted" => {
                    self.is_deleted = true;
                }
                _ => {}
            }
        }


        if self.object_identifier != "SID" {
            dn_sid.insert(
                self.properties.distinguishedname.to_string(),
                self.object_identifier.to_string()
            );

            sid_type.insert(self.object_identifier.to_string(), ftype.to_string());
        }



        Ok(())
    }
}


#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct FspProperties {
   domain: String,
   name: String,
   distinguishedname: String,
   domainsid: String,
   isaclprotected: bool,
   highvalue: bool,
   description: Option<String>,
   whencreated: i64,
}

impl FspProperties {

   pub fn new(domain: String) -> Self { 
      Self { 
         domain,
         whencreated: -1,
         ..Default::default() }
   }


   pub fn domain(&self) -> &String {
      &self.domain
   }
   pub fn name(&self) -> &String {
      &self.name
   }
   pub fn distinguishedname(&self) -> &String {
      &self.distinguishedname
   }
   pub fn domainsid(&self) -> &String {
      &self.domainsid
   }
   pub fn highvalue(&self) -> &bool {
      &self.highvalue
   }
   pub fn description(&self) -> &Option<String> {
      &self.description
   }
   pub fn whencreated(&self) -> &i64 {
      &self.whencreated
   }


   pub fn domain_mut(&mut self) -> &mut String {
      &mut self.domain
   }
   pub fn name_mut(&mut self) -> &mut String {
      &mut self.name
   }
   pub fn distinguishedname_mut(&mut self) -> &mut String {
      &mut self.distinguishedname
   }
   pub fn domainsid_mut(&mut self) -> &mut String {
      &mut self.domainsid
   }
   pub fn highvalue_mut(&mut self) -> &mut bool {
      &mut self.highvalue
   }
   pub fn description_mut(&mut self) -> &mut Option<String> {
      &mut self.description
   }
   pub fn whencreated_mut(&mut self) -> &mut i64 {
      &mut self.whencreated
   }
}

impl LdapObject for Fsp {

    fn to_json(&self) -> Value {
        serde_json::to_value(self).unwrap()
    }


    fn get_object_identifier(&self) -> &String {
        &self.object_identifier
    }
    fn get_is_acl_protected(&self) -> &bool {
        &self.is_acl_protected
    }
    fn get_aces(&self) -> &Vec<AceTemplate> {
        &self.aces
    }
    fn get_spntargets(&self) -> &Vec<SPNTarget> {
        panic!("Not used by current object.");
    }
    fn get_allowed_to_delegate(&self) -> &Vec<Member> {
        panic!("Not used by current object.");
    }
    fn get_links(&self) -> &Vec<Link> {
        panic!("Not used by current object.");
    }
    fn get_contained_by(&self) -> &Option<Member> {
        &self.contained_by
    }
    fn get_child_objects(&self) -> &Vec<Member> {
        panic!("Not used by current object.");
    }
    fn get_haslaps(&self) -> &bool {
        &false
    }
    

    fn get_aces_mut(&mut self) -> &mut Vec<AceTemplate> {
        &mut self.aces
    }
    fn get_spntargets_mut(&mut self) -> &mut Vec<SPNTarget> {
        panic!("Not used by current object.");
    }
    fn get_allowed_to_delegate_mut(&mut self) -> &mut Vec<Member> {
        panic!("Not used by current object.");
    }
    

    fn set_is_acl_protected(&mut self, is_acl_protected: bool) {
        self.is_acl_protected = is_acl_protected;
        self.properties.isaclprotected = is_acl_protected;
    }
    fn set_aces(&mut self, aces: Vec<AceTemplate>) {
        self.aces = aces;
    }
    fn set_spntargets(&mut self, _spn_targets: Vec<SPNTarget>) {

    }
    fn set_allowed_to_delegate(&mut self, _allowed_to_delegate: Vec<Member>) {

    }
    fn set_links(&mut self, _links: Vec<Link>) {

    }
    fn set_contained_by(&mut self, contained_by: Option<Member>) {
        self.contained_by = contained_by;
    }
    fn set_child_objects(&mut self, _child_objects: Vec<Member>) {

    }
}