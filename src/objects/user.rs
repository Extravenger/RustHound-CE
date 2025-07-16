use serde_json::value::Value;
use serde::{Deserialize, Serialize};
use ldap3::SearchEntry;
use log::{debug, error, trace};
use std::collections::HashMap;
use x509_parser::prelude::*;
use std::error::Error;

use crate::enums::regex::{OBJECT_SID_RE1, SID_PART1_RE1};
use crate::objects::common::{LdapObject, AceTemplate, SPNTarget, Link, Member};
use crate::utils::date::{convert_timestamp, string_to_epoch};
use crate::utils::crypto::convert_encryption_types;
use crate::enums::acl::{parse_ntsecuritydescriptor, parse_gmsa};
use crate::enums::secdesc::LdapSid;
use crate::enums::sid::sid_maker;
use crate::enums::spntasks::check_spn;
use crate::enums::uacflags::get_flag;


#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct User {
    #[serde(rename ="ObjectIdentifier")]
    object_identifier: String,
    #[serde(rename ="IsDeleted")]
    is_deleted: bool,
    #[serde(rename ="IsACLProtected")]
    is_acl_protected: bool,
    #[serde(rename ="Properties")]
    properties: UserProperties,
    #[serde(rename ="PrimaryGroupSID")]
    primary_group_sid: String,
    #[serde(rename ="SPNTargets")]
    spn_targets: Vec<SPNTarget>,
    #[serde(rename ="UnconstrainedDelegation")]
    unconstrained_delegation: bool,
    #[serde(rename ="DomainSID")]
    domain_sid: String,
    #[serde(rename ="Aces")]
    aces: Vec<AceTemplate>,
    #[serde(rename ="AllowedToDelegate")]
    allowed_to_delegate: Vec<Member>,
    #[serde(rename ="HasSIDHistory")]
    has_sid_history: Vec<String>,
    #[serde(rename ="ContainedBy")]
    contained_by: Option<Member>,
}

impl User {

    pub fn new() -> Self { 
        Self { ..Default::default()} 
    }


    pub fn properties(&self) -> &UserProperties {
        &self.properties
    }
    pub fn aces(&self) -> &Vec<AceTemplate> {
        &self.aces
    }


    pub fn properties_mut(&mut self) -> &mut UserProperties {
        &mut self.properties
    }
    pub fn aces_mut(&mut self) -> &mut Vec<AceTemplate> {
        &mut self.aces
    }
    pub fn object_identifier_mut(&mut self) -> &mut String {
        &mut self.object_identifier
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


        debug!("Parse user: {result_dn}");


        for (key, value) in &result_attrs {
            trace!("  {key:?}:{value:?}");
        }

        for (key, value) in &result_bin {
            trace!("  {key:?}:{value:?}");
        }


        self.properties.domain = domain.to_uppercase();
        self.properties.distinguishedname = result_dn;
        self.properties.enabled = true;
        self.domain_sid = domain_sid.to_string();


        let mut group_id: String ="".to_owned();
        for (key, value) in &result_attrs {
            match key.as_str() {
                "sAMAccountName" => {
                    let name = &value[0];
                    let email = format!("{}@{}",name.to_owned(),domain);
                    self.properties.name = email.to_uppercase();
                    self.properties.samaccountname = name.to_string();
                }
                "description" => {
                    self.properties.description = Some(value[0].to_owned());
                }
                "mail" => {
                    self.properties.email = value[0].to_owned();
                }
                "title" => {
                    self.properties.title = value[0].to_owned();
                }
                "userPassword" => {
                    self.properties.userpassword = value[0].to_owned();
                }
                "unixUserPassword" => {
                    self.properties.unixpassword = value[0].to_owned();
                }
                "unicodepwd" => {
                    self.properties.unicodepassword = value[0].to_owned();
                }
                "sfupassword" => {

                }
                "displayName" => {
                    self.properties.displayname = value[0].to_owned();
                }
                "adminCount" => {
                    let isadmin = &value[0];
                    let mut admincount = false;
                    if isadmin =="1" {
                        admincount = true;
                    }
                    self.properties.admincount = admincount;
                }
                "homeDirectory" => {
                    self.properties.homedirectory = value[0].to_owned();
                }
                "scriptpath" => {
                    self.properties.logonscript = value[0].to_owned();
                }
                "userAccountControl" => {
                    let uac = &value[0].parse::<u32>().unwrap_or(0);
                    self.properties.useraccountcontrol = *uac;
                    let uac_flags = get_flag(*uac);

                    for flag in uac_flags {
                        if flag.contains("AccountDisable") {
                            self.properties.enabled = false;
                        };

                        if flag.contains("PasswordNotRequired") {
                            self.properties.passwordnotreqd = true;
                        };
                        if flag.contains("DontExpirePassword") {
                            self.properties.pwdneverexpires = true;
                        };
                        if flag.contains("DontReqPreauth") {
                            self.properties.dontreqpreauth = true;
                        };

                        if flag.contains("TrustedForDelegation") {
                            self.properties.unconstraineddelegation = true;
                            self.unconstrained_delegation = true;
                        };
                        if flag.contains("NotDelegated") {
                            self.properties.sensitive = true;
                        };

                        if flag.contains("TrustedToAuthForDelegation") {
                            self.properties.trustedtoauth = true;
                        };
                    }
                }
                "msDS-AllowedToDelegateTo"  => {



                    let mut vec_members2: Vec<Member> = Vec::new();
                    for objet in value {
                        let mut member_allowed_to_delegate = Member::new();
                        let split = objet.split("/");
                        let fqdn = split.collect::<Vec<&str>>()[1];
                        let mut checker = false;
                        for member in &vec_members2 {
                          if member.object_identifier().contains(fqdn.to_uppercase().as_str()) {
                                 checker = true;
                         }
                       }
                        if !checker {
                          *member_allowed_to_delegate.object_identifier_mut() = fqdn.to_uppercase().to_owned().to_uppercase();
                          *member_allowed_to_delegate.object_type_mut() ="Computer".to_owned();
                          vec_members2.push(member_allowed_to_delegate.to_owned()); 
                       }
                  }

                    self.allowed_to_delegate = vec_members2;
                }
                "lastLogon" => {
                    let lastlogon = &value[0].parse::<i64>().unwrap_or(0);
                    if lastlogon.is_positive() {
                        let epoch = convert_timestamp(*lastlogon);
                        self.properties.lastlogon = epoch;
                    }
                }
                "lastLogonTimestamp" => {
                    let lastlogontimestamp = &value[0].parse::<i64>().unwrap_or(0);
                    if lastlogontimestamp.is_positive() {
                        let epoch = convert_timestamp(*lastlogontimestamp);
                        self.properties.lastlogontimestamp = epoch;
                    }
                }
                "pwdLastSet" => {
                    let pwdlastset = &value[0].parse::<i64>().unwrap_or(0);
                    if pwdlastset.is_positive() {
                        let epoch = convert_timestamp(*pwdlastset);
                        self.properties.pwdlastset = epoch;
                    }
                }
                "whenCreated" => {
                    let epoch = string_to_epoch(&value[0])?;
                    if epoch.is_positive() {
                        self.properties.whencreated = epoch;
                    }
                }
                "servicePrincipalName" => {

                    let mut targets: Vec<SPNTarget> = Vec::new();
                    let mut result: Vec<String> = Vec::new();
                    let mut added: bool = false;
                    for v in value {
                        result.push(v.to_owned());

                        let _target = match check_spn(v).to_owned() {
                            Some(_target) => {
                                if !added {
                                   targets.push(_target.to_owned());
                                   added = true;
                                }
                            },
                            None => {}
                        };
                    }
                    self.properties.serviceprincipalnames = result;
                    self.properties.hasspn = true;
                    self.spn_targets = targets;
                }
                "primaryGroupID" => {
                    group_id = value[0].to_owned();
                }
                "IsDeleted" => {



                    self.is_deleted = true;
                }
                "msDS-SupportedEncryptionTypes" => {
                    self.properties.supportedencryptiontypes = convert_encryption_types(value[0].parse::<i32>().unwrap_or(0));
                }
                 _ => {}
            }
        }


        let mut sid: String = "".to_owned();
        for (key, value) in &result_bin {
            match key.as_str() {
                "objectSid" => {
                    sid = sid_maker(LdapSid::parse(&value[0]).unwrap().1, domain);
                    self.object_identifier = sid.to_owned();

                    for domain_sid in OBJECT_SID_RE1.captures_iter(&sid) {
                        self.properties.domainsid = domain_sid[0].to_owned().to_string();
                    }
                }
                "nTSecurityDescriptor" => {

                    let relations_ace = parse_ntsecuritydescriptor(
                        self,
                        &value[0],
                        "User",
                        &result_attrs,
                        &result_bin,
                        domain,
                    );
                    self.aces_mut().extend(relations_ace);
                }
                "sIDHistory" => {


                    let mut list_sid_history: Vec<String> = Vec::new();
                    for bsid in value {
                        debug!("sIDHistory: {:?}", &bsid);
                        list_sid_history.push(sid_maker(LdapSid::parse(bsid).unwrap().1, domain));

                    }
                    self.properties.sidhistory = list_sid_history;
                }
                "msDS-GroupMSAMembership" => {

                    let mut relations_ace = parse_ntsecuritydescriptor(
                        self,
                        &value[0],
                        "User",
                        &result_attrs,
                        &result_bin,
                        domain,
                    );


                    parse_gmsa(&mut relations_ace, self);

                }
                "userCertificate" => {


                    let res = X509Certificate::from_der(&value[0]);
                    match res {
                        Ok((_rem, _cert)) => {},
                        _ => error!("CA x509 certificate parsing failed: {:?}", res),
                    }
                }
                _ => {}
            }
        }


        #[allow(irrefutable_let_patterns)]
        if let id = group_id {
            if let Some(part1) = SID_PART1_RE1.find(&sid) {
                self.primary_group_sid = format!("{}{}", part1.as_str(), id);
            } else {
                eprintln!("[!] Regex did not match any part of the SID");
            }
        }


        dn_sid.insert(
            self.properties.distinguishedname.to_owned(),
            self.object_identifier.to_owned(),
        );

        sid_type.insert(
            self.object_identifier.to_owned(),
            "User".to_string(),
        );



        Ok(())
    }
}


impl LdapObject for User {

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
        &self.spn_targets
    }
    fn get_allowed_to_delegate(&self) -> &Vec<Member> {
        &self.allowed_to_delegate
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
        &mut self.spn_targets
    }
    fn get_allowed_to_delegate_mut(&mut self) -> &mut Vec<Member> {
        &mut self.allowed_to_delegate
    }


    fn set_is_acl_protected(&mut self, is_acl_protected: bool) {
        self.is_acl_protected = is_acl_protected;
        self.properties.isaclprotected = is_acl_protected;
    }
    fn set_aces(&mut self, aces: Vec<AceTemplate>) {
        self.aces = aces;
    }
    fn set_spntargets(&mut self, spn_targets: Vec<SPNTarget>) {
        self.spn_targets = spn_targets;
    }
    fn set_allowed_to_delegate(&mut self, allowed_to_delegate: Vec<Member>) {
        self.allowed_to_delegate = allowed_to_delegate;
    }
    fn set_links(&mut self, _links: Vec<Link>) {

    }
    fn set_contained_by(&mut self, contained_by: Option<Member>) {
        self.contained_by = contained_by;
    }
    fn set_child_objects(&mut self, _child_objects: Vec<Member>) {

    }
}


#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct UserProperties {
    domain: String,
    name: String,
    domainsid: String,
    isaclprotected: bool,
    distinguishedname: String,
    highvalue: bool,
    description: Option<String>,
    whencreated: i64,
    sensitive: bool,
    dontreqpreauth: bool,
    passwordnotreqd: bool,
    unconstraineddelegation: bool,
    pwdneverexpires: bool,
    enabled: bool,
    trustedtoauth: bool,
    lastlogon: i64,
    lastlogontimestamp: i64,
    pwdlastset: i64,
    serviceprincipalnames: Vec<String>,
    hasspn: bool,
    displayname: String,
    email: String,
    title: String,
    homedirectory: String,
    logonscript: String,
    useraccountcontrol: u32,
    samaccountname: String,
    userpassword: String,
    unixpassword: String,
    unicodepassword: String,
    sfupassword: String,
    admincount: bool,
    supportedencryptiontypes: Vec<String>,
    sidhistory: Vec<String>,
    allowedtodelegate: Vec<String>
}

impl UserProperties {

    pub fn name(&self) -> &String {
        &self.name
    }
    pub fn domainsid(&self) -> &String {
        &self.domainsid
    }
    pub fn isaclprotected(&self) -> &bool {
        &self.isaclprotected
    }


    pub fn name_mut(&mut self) -> &mut String {
        &mut self.name
    }
    pub fn domainsid_mut(&mut self) -> &mut String {
        &mut self.domainsid
    }
    pub fn isaclprotected_mut(&mut self) -> &mut bool {
        &mut self.isaclprotected
    }
}