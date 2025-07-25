use serde_json::value::Value;
use serde::{Deserialize, Serialize};
use ldap3::SearchEntry;
use log::{debug, trace};
use std::collections::HashMap;
use std::error::Error;

use crate::objects::common::{LdapObject, AceTemplate, Link, SPNTarget, Member};
use crate::enums::decode_guid_le;
use crate::enums::acl::parse_ntsecuritydescriptor;
use crate::utils::date::string_to_epoch;


#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct Gpo {
    #[serde(rename = "Properties")]
    properties: GpoProperties,
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
    #[serde(rename = "Links")]
    links: Vec<Link>,
}

impl Gpo {

    pub fn new() -> Self { 
        Self { ..Default::default() } 
    }
    


    pub fn parse(
        &mut self,
        result: SearchEntry,
        domain: &str,
        dn_sid: &mut HashMap<String, String>,
        sid_type: &mut HashMap<String, String>,
        domain_sid: &str
    ) -> Result<(), Box<dyn Error>> {
        let result_dn: String = result.dn.to_uppercase();
        let result_attrs: HashMap<String, Vec<String>> = result.attrs;
        let result_bin: HashMap<String, Vec<Vec<u8>>> = result.bin_attrs;


        debug!("Parse gpo: {result_dn}");


        for (key, value) in &result_attrs {
            trace!("  {key:?}:{value:?}");
        }

        for (key, value) in &result_bin {
            trace!("  {key:?}:{value:?}");
        }


        self.properties.domain = domain.to_uppercase();
        self.properties.distinguishedname = result_dn;
        self.properties.domainsid = domain_sid.to_string();


        for (key, value) in &result_attrs {
            match key.as_str() {
                "displayName" => {
                    let name = &value[0];
                    let email = format!("{}@{}", name.to_owned(), domain);
                    self.properties.name = email.to_uppercase();
                }
                "description" => {
                    self.properties.description = value.first().cloned();
                }
                "whenCreated" => {
                    let epoch = string_to_epoch(&value[0])?;
                    if epoch.is_positive() {
                        self.properties.whencreated = epoch;
                    }
                }
                "gPCFileSysPath" => {
                    self.properties.gpcpath = value[0].to_owned();
                }
                "IsDeleted" => {
                    self.is_deleted = true;
                }
                _ => {}
            }
        }


        for (key, value) in &result_bin {
            match key.as_str() {
                "objectGUID" => {

                    self.object_identifier = decode_guid_le(&value[0]).to_owned();
                }
                "nTSecurityDescriptor" => {

                    let relations_ace = parse_ntsecuritydescriptor(
                        self,
                        &value[0],
                        "Gpo",
                        &result_attrs,
                        &result_bin,
                        domain,
                    );
                    self.aces = relations_ace;
                }
                _ => {}
            }
        }


        dn_sid.insert(
            self.properties.distinguishedname.to_string(),
            self.object_identifier.to_string(),
        );

        sid_type.insert(
            self.object_identifier.to_string(),
            "Gpo".to_string(),
        );



        Ok(())
    }
}

impl LdapObject for Gpo {

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
    fn set_links(&mut self, links: Vec<Link>) {
        self.links = links;
    }
    fn set_contained_by(&mut self, contained_by: Option<Member>) {
        self.contained_by = contained_by;
    }
    fn set_child_objects(&mut self, _child_objects: Vec<Member>) {

    }
}


#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct GpoProperties {
   domain: String,
   name: String,
   distinguishedname: String,
   domainsid: String,
   isaclprotected: bool,
   highvalue: bool,
   description: Option<String>,
   whencreated: i64,
   gpcpath: String
}