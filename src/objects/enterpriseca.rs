use colored::Colorize;
use serde::{Deserialize, Serialize};
use serde_json::value::Value;
use x509_parser::oid_registry::asn1_rs::oid;
use x509_parser::prelude::*;
use ldap3::SearchEntry;
use log::{debug, error, info, trace};
use std::collections::HashMap;
use std::error::Error;

use crate::enums::{
    MaskFlags, SecurityDescriptor, AceFormat, Acl,
    decode_guid_le, parse_ntsecuritydescriptor, sid_maker, parse_ca_security
};
use crate::json::checker::common::get_name_from_full_distinguishedname;
use crate::objects::common::{LdapObject, AceTemplate, SPNTarget, Link, Member};
use crate::utils::crypto::calculate_sha1;
use crate::utils::date::string_to_epoch;


#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct EnterpriseCA {
    #[serde(rename = "Properties")]
    properties: EnterpriseCAProperties,
    #[serde(rename = "HostingComputer")]
    hosting_computer: String,
    #[serde(rename = "CARegistryData")]
    ca_registry_data: CARegistryData,
    #[serde(rename = "EnabledCertTemplates")]
    enabled_cert_templates: Vec<Member>,
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

impl EnterpriseCA {

    pub fn new() -> Self { 
        Self { ..Default::default() } 
    }


    pub fn enabled_cert_templates(&self) -> &Vec<Member> {
        &self.enabled_cert_templates
    }


    pub fn enabled_cert_templates_mut(&mut self) -> &mut Vec<Member> {
        &mut self.enabled_cert_templates
    }


    pub fn parse(
        &mut self,
        result: SearchEntry,
        domain: &str,
        dn_sid: &mut HashMap<String, String>,
        sid_type: &mut HashMap<String, String>,
        domain_sid: &str,
    ) -> Result<(), Box<dyn Error>> {
        let result_dn: String = result.dn.to_uppercase();
        let result_attrs: HashMap<String, Vec<String>> = result.attrs;
        let result_bin: HashMap<String, Vec<Vec<u8>>> = result.bin_attrs;


        debug!("Parse EnterpriseCA: {result_dn}");


        for (key, value) in &result_attrs {
            trace!("  {key:?}:{value:?}");
        }

        for (key, value) in &result_bin {
            trace!("  {key:?}:{value:?}");
        }


        self.properties.domain = domain.to_uppercase();
        self.properties.distinguishedname = result_dn;
        self.properties.domainsid = domain_sid.to_string();
        let ca_name = get_name_from_full_distinguishedname(&self.properties.distinguishedname);
        self.properties.caname = ca_name;


        for (key, value) in &result_attrs {
            match key.as_str() {
                "name" => {
                    let name = format!("{}@{}", &value[0], domain);
                    self.properties.name = name.to_uppercase();
                }
                "description" => {
                    self.properties.description = Some(value[0].to_owned());
                }
                "dNSHostName" => {
                    self.properties.dnshostname = value[0].to_owned();
                }
                "certificateTemplates" => {
                    if value.is_empty() {
                        error!("No certificate templates enabled for {}", self.properties.caname);
                    } else {

                        info!("Found {} enabled certificate templates", value.len().to_string().bold());
                        trace!("Enabled certificate templates: {:?}", value);
                        let enabled_templates: Vec<Member> = value.iter().map(|template_name| {
                            let mut member = Member::new();
                            *member.object_identifier_mut() = template_name.to_owned();
                            *member.object_type_mut() = String::from("CertTemplate");

                            member
                        }).collect();
                        self.enabled_cert_templates = enabled_templates;
                    }
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
                        "EnterpriseCA",
                        &result_attrs,
                        &result_bin,
                        domain,
                    );

                    self.aces = relations_ace;

                    self.hosting_computer = Self::get_hosting_computer(&value[0], domain);

                    let ca_security_data = parse_ca_security(&value[0], &self.hosting_computer, domain);
                    if !ca_security_data.is_empty() {
                        let ca_security = CASecurity {
                            data: ca_security_data,
                            collected: true,
                            failure_reason: None,
                        };
                        self.properties.casecuritycollected = true;
                        let ca_registry_data = CARegistryData::new(ca_security);
                        self.ca_registry_data = ca_registry_data;
                    } else {
                        let ca_security = CASecurity {
                            data: Vec::new(),
                            collected: false,
                            failure_reason: Some(String::from("Failed to get CASecurity!"))
                        };
                        self.properties.casecuritycollected = false;
                        let ca_registry_data = CARegistryData::new(ca_security);
                        self.ca_registry_data = ca_registry_data;
                    }
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
                                            }
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
                self.properties.distinguishedname.to_string(),
                self.object_identifier.to_string(),
            );

            sid_type.insert(
                self.object_identifier.to_string(),
                "EnterpriseCA".to_string(),
            );
        }



        Ok(())
    }


    fn get_hosting_computer(
        nt: &[u8],
        domain: &str,
    ) -> String {
        let mut hosting_computer = String::from("Not found");
        let blacklist_sid = [

            "-544", // Administrators
            "-519", // Enterprise Administrators
            "-512", // Domain Admins
        ];
        let secdesc: SecurityDescriptor = SecurityDescriptor::parse(nt).unwrap().1;
        if secdesc.offset_dacl as usize != 0 
        {
            let res = Acl::parse(&nt[secdesc.offset_dacl as usize..]);
            match res {
                Ok(_res) => {
                    let dacl = _res.1;
                    let aces = dacl.data;
                    for ace in aces {
                        if ace.ace_type == 0x00 {
                            let sid = sid_maker(AceFormat::get_sid(ace.data.to_owned()).unwrap(), domain);
                            let mask = match AceFormat::get_mask(&ace.data) {
                                Some(mask) => mask,
                                None => continue,
                            };
                            if (MaskFlags::MANAGE_CERTIFICATES.bits() | mask) == mask
                            && !blacklist_sid.iter().any(|blacklisted| sid.ends_with(blacklisted)) 
                            {

                                hosting_computer = sid;
                                return hosting_computer
                            }
                        }
                    }
                },
                Err(err) => error!("Error. Reason: {err}")
            }
        }
        hosting_computer
    }
}

impl LdapObject for EnterpriseCA {

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
pub struct EnterpriseCAProperties {
    domain: String,
    name: String,
    distinguishedname: String,
    domainsid: String,
    isaclprotected: bool,
    description: Option<String>,
    whencreated: i64,
    flags: String,
    caname: String,
    dnshostname: String,
    certthumbprint: String,
    certname: String,
    certchain: Vec<String>,
    hasbasicconstraints: bool,
    basicconstraintpathlength: u32,
    unresolvedpublishedtemplates: Vec<String>,
    casecuritycollected: bool,
    enrollmentagentrestrictionscollected: bool,
    isuserspecifiessanenabledcollected: bool,
    roleseparationenabledcollected: bool,
}

impl Default for EnterpriseCAProperties {
    fn default() -> EnterpriseCAProperties {
        EnterpriseCAProperties {
            domain: String::from(""),
            name: String::from(""),
            distinguishedname: String::from(""),
            domainsid: String::from(""),
            isaclprotected: false,
            description: None,
            whencreated: -1,
            flags: String::from(""),
            caname: String::from(""),
            dnshostname: String::from(""),
            certthumbprint: String::from(""),
            certname: String::from(""),
            certchain: Vec::new(),
            hasbasicconstraints: false,
            basicconstraintpathlength: 0,
            unresolvedpublishedtemplates: Vec::new(),
            casecuritycollected: false,
            enrollmentagentrestrictionscollected: false,
            isuserspecifiessanenabledcollected: false,
            roleseparationenabledcollected: false,
       }
    }
 }


#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct CARegistryData {
    #[serde(rename = "CASecurity")]
    ca_security: CASecurity,
    #[serde(rename = "EnrollmentAgentRestrictions")]
    enrollment_agent_restrictions: EnrollmentAgentRestrictions,
    #[serde(rename = "IsUserSpecifiesSanEnabled")]
    is_user_specifies_san_enabled: IsUserSpecifiesSanEnabled,
    #[serde(rename = "RoleSeparationEnabled")]
    role_separation_enabled: RoleSeparationEnabled,
}

impl CARegistryData {
    pub fn new(
        ca_security: CASecurity,
    ) -> Self { 
        Self { 
            ca_security,
            ..Default::default()
        }
    }
}


#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CASecurity {
    #[serde(rename = "Data")]
    data: Vec<AceTemplate>,
    #[serde(rename = "Collected")]
    collected: bool,
    #[serde(rename = "FailureReason")]
    failure_reason: Option<String>,
}


impl Default for CASecurity {
    fn default() -> CASecurity {
        CASecurity {
            data: Vec::new(),
            collected: true,
            failure_reason: None,
        }
    }
}


#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EnrollmentAgentRestrictions {
    #[serde(rename = "Restrictions")]
    restrictions: Vec<String>, // data to validate
    #[serde(rename = "Collected")]
    collected: bool,
    #[serde(rename = "FailureReason")]
    failure_reason: Option<String>,
}

impl Default for EnrollmentAgentRestrictions {
    fn default() -> EnrollmentAgentRestrictions {
        EnrollmentAgentRestrictions {
            restrictions: Vec::new(),
            collected: true,
            failure_reason: None,
        }
    }
}


#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct IsUserSpecifiesSanEnabled {
    #[serde(rename = "Value")]
    value: bool,
    #[serde(rename = "Collected")]
    collected: bool,
    #[serde(rename = "FailureReason")]
    failure_reason: Option<String>,
}

impl Default for IsUserSpecifiesSanEnabled {
    fn default() -> IsUserSpecifiesSanEnabled {
        IsUserSpecifiesSanEnabled {
            value: false,
            collected: true,
            failure_reason: None,
        }
    }
}


#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RoleSeparationEnabled {
    #[serde(rename = "Value")]
    value: bool,
    #[serde(rename = "Collected")]
    collected: bool,
    #[serde(rename = "FailureReason")]
    failure_reason: Option<String>,
}

impl Default for RoleSeparationEnabled {
    fn default() -> RoleSeparationEnabled {
        RoleSeparationEnabled {
            value: false,
            collected: true,
            failure_reason: None,
        }
    }
}