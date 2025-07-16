use serde_json::value::Value;
use serde::{Deserialize, Serialize};
use x509_parser::oid_registry::asn1_rs::oid;
use x509_parser::prelude::*;
use ldap3::SearchEntry;
use log::{debug, error, trace};
use std::collections::HashMap;
use std::error::Error;

use crate::objects::common::{LdapObject, AceTemplate, SPNTarget, Link, Member};
use crate::enums::{decode_guid_le, parse_ntsecuritydescriptor};
use crate::utils::date::string_to_epoch;
use crate::utils::crypto::calculate_sha1;


#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct AIACA {
    #[serde(rename = "Properties")]
    properties: AIACAProperties,
    #[serde(rename = "DomainSID")]
    domain_sid: String,
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

impl AIACA {

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


        debug!("Parse AIACA: {result_dn}");


        for (key, value) in &result_attrs {
            trace!("  {key:?}:{value:?}");
        }

        for (key, value) in &result_bin {
            trace!("  {key:?}:{value:?}");
        }



        self.properties.domain = domain.to_uppercase();
        self.properties.distinguishedname = result_dn;    
        self.properties.domainsid = domain_sid.to_string();
        self.domain_sid = domain_sid.to_string();


        for (key, value) in &result_attrs {
            match key.as_str() {
                "name" => {
                    let name = format!("{}@{}",&value[0],domain);
                    self.properties.name = name.to_uppercase();
                }
                "description" => {
                    self.properties.description = Some(value[0].to_owned());
                }
                "whenCreated" => {
                    let epoch = string_to_epoch(&value[0])?;
                    if epoch.is_positive() {
                        self.properties.whencreated = epoch;
                    }
                }
                "IsDeleted" => {
                    self.is_deleted = true;
                }
                "crossCertificatePair" => {
                    self.properties.hascrosscertificatepair = true;

                }
                _ => {}
            }
        }


        for (key, value) in &result_bin {
            match key.as_str() {
                "objectGUID" => {

                    let guid = decode_guid_le(&value[0]);
                    self.object_identifier = guid.to_owned();
                }
                "nTSecurityDescriptor" => {

                    let relations_ace = parse_ntsecuritydescriptor(
                        self,
                        &value[0],
                        "AIACA",
                        &result_attrs,
                        &result_bin,
                        domain,
                    );
                    self.aces = relations_ace;
                }
                "cACertificate" => {

                    let certsha1: String = calculate_sha1(&value[0]);
                    self.properties.certthumbprint = certsha1.to_owned();
                    self.properties.certname = certsha1.to_owned();
                    self.properties.certchain = vec![certsha1.to_owned()];


                    let res = X509Certificate::from_der(&value[0]);
                    match res {
                        Ok((_rem, cert)) => {

                            for ext in cert.extensions() {

                                if &ext.oid == &oid!(2.5.29.19) {

                                    if let ParsedExtension::BasicConstraints(basic_constraints) = &ext.parsed_extension() {
                                        let _ca = &basic_constraints.ca;
                                        let _path_len_constraint = &basic_constraints.path_len_constraint;


                                        match _path_len_constraint {
                                            Some(_path_len_constraint) => {
                                                if _path_len_constraint > &0 {
                                                    self.properties.hasbasicconstraints = true;
                                                    self.properties.basicconstraintpathlength = _path_len_constraint.to_owned();

                                                } else {
                                                    self.properties.hasbasicconstraints = false;
                                                    self.properties.basicconstraintpathlength = 0;
                                                }
                                            },
                                            None => {
                                                self.properties.hasbasicconstraints = false;
                                                self.properties.basicconstraintpathlength = 0;
                                            }
                                        }
                                    }
                                }
                            }
                        },
                        _ => error!("CA x509 certificate parsing failed: {:?}", res),
                    }
                }
                _ => {}
            }
        }


        if self.object_identifier != "SID" {
            dn_sid.insert(
                self.properties.distinguishedname.to_owned(),
                self.object_identifier.to_owned()
            );

            sid_type.insert(
                self.object_identifier.to_owned(),
                "AIACA".to_string()
            );
        }



        Ok(())
    }
}

impl LdapObject for AIACA {

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



#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AIACAProperties {
   domain: String,
   name: String,
   distinguishedname: String,
   domainsid: String,
   isaclprotected: bool,
   description: Option<String>,
   whencreated: i64,
   crosscertificatepair: Vec<String>,
   hascrosscertificatepair: bool,
   certthumbprint: String,
   certname: String,
   certchain: Vec<String>,
   hasbasicconstraints: bool,
   basicconstraintpathlength: u32,
}

impl Default for AIACAProperties {
    fn default() -> AIACAProperties {
        AIACAProperties {
            domain: String::from(""),
            name: String::from(""),
            distinguishedname: String::from(""),
            domainsid: String::from(""),
            isaclprotected: false,
            description: None,
            whencreated: -1,
            crosscertificatepair: Vec::new(),
            hascrosscertificatepair: false,
            certthumbprint: String::from(""),
            certname: String::from(""),
            certchain: Vec::new(),
            hasbasicconstraints: false,
            basicconstraintpathlength: 0,
       }
    }
}