use std::collections::HashMap;

use ldap3::SearchEntry;
use log::trace;
use serde_json::{json,value::Value};
use serde::{Deserialize, Serialize};



pub trait LdapObject {

   fn to_json(&self) -> Value;


   fn get_object_identifier(&self) -> &String;
   fn get_is_acl_protected(&self) -> &bool;
   fn get_aces(&self) -> &Vec<AceTemplate>;
   fn get_spntargets(&self) -> &Vec<SPNTarget>;
   fn get_allowed_to_delegate(&self) -> &Vec<Member>;
   fn get_links(&self) -> &Vec<Link>;
   fn get_contained_by(&self) -> &Option<Member>;
   fn get_child_objects(&self) -> &Vec<Member>;

   fn get_haslaps(&self) -> &bool;


   fn get_aces_mut(&mut self) -> &mut Vec<AceTemplate>;
   fn get_spntargets_mut(&mut self) -> &mut Vec<SPNTarget>;
   fn get_allowed_to_delegate_mut(&mut self) -> &mut Vec<Member>;


   fn set_is_acl_protected(&mut self, is_acl_protected: bool);
   fn set_aces(&mut self, aces: Vec<AceTemplate>);
   fn set_spntargets(&mut self, spn_targets: Vec<SPNTarget>);
   fn set_allowed_to_delegate(&mut self, allowed_to_delegate: Vec<Member>);
   fn set_links(&mut self, links: Vec<Link>);
   fn set_contained_by(&mut self, contained_by: Option<Member>);
   fn set_child_objects(&mut self, child_objects: Vec<Member>);
}


#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct LocalGroup {
   #[serde(rename = "ObjectIdentifier")]
   object_identifier: String,
   #[serde(rename = "Results")]
   results: Vec<Member>,
   #[serde(rename = "LocalNames")]
   local_names: Vec<String>,
   #[serde(rename = "Collected")]
   collected: bool,
   #[serde(rename = "FailureReason")]
   failure_reason: Option<String>,
}

impl LocalGroup {

   pub fn new() -> Self { 
      Self { 
         ..Default::default()
      }
   }


   pub fn object_identifier(&self) -> &String {
      &self.object_identifier
   }
   pub fn results(&self) -> &Vec<Member> {
      &self.results
   }
   pub fn local_names(&self) -> &Vec<String> {
      &self.local_names
   }
   pub fn collected(&self) -> &bool {
      &self.collected
   }
   pub fn failure_reason(&self) -> &Option<String> {
      &self.failure_reason
   }


   pub fn object_identifier_mut(&mut self) -> &mut String {
      &mut self.object_identifier
   }
   pub fn results_mut(&mut self) -> &mut Vec<Member> {
      &mut self.results
   }
   pub fn local_names_mut(&mut self) -> &mut Vec<String> {
      &mut self.local_names
   }
   pub fn collected_mut(&mut self) -> &mut bool {
      &mut self.collected
   }
   pub fn failure_reason_mut(&mut self) -> &mut Option<String> {
      &mut self.failure_reason
   }
}


#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Session {
   #[serde(rename = "Results")]
   results: Vec<UserComputerSession>,
   #[serde(rename = "Collected", default = "default_true")]
   collected: bool,
   #[serde(rename = "FailureReason")]
   failure_reason: Option<String>,
}

impl Default for Session {

   fn default() -> Session {
      Session {
         results: Vec::new(),
         collected: true,
         failure_reason: None,
       }
   }
}

impl Session {

   pub fn new() -> Self { 
      Self { 
         collected: true,
         ..Default::default()
      }
   }


   pub fn results(&self) -> &Vec<UserComputerSession> {
      &self.results
   }
   pub fn collected(&self) -> &bool {
      &self.collected
   }
   pub fn failure_reason(&self) -> &Option<String> {
      &self.failure_reason
   }


   pub fn results_mut(&mut self) -> &mut Vec<UserComputerSession> {
      &mut self.results
   }
   pub fn collected_mut(&mut self) -> &mut bool {
      &mut self.collected
   }
   pub fn failure_reason_mut(&mut self) -> &mut Option<String> {
      &mut self.failure_reason
   }
}


#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct UserComputerSession {
   #[serde(rename = "UserSID")]
   user_sid: String,
   #[serde(rename = "ComputerSID")]
   computer_sid: String,
}

impl UserComputerSession {

   pub fn new() -> Self { 
      Self { 
         ..Default::default()
      }
   }


   pub fn user_sid(&self) -> &String {
      &self.user_sid
   }
   pub fn computer_sid(&self) -> &String {
      &self.computer_sid
   }


   pub fn user_sid_mut(&mut self) -> &mut String {
      &mut self.user_sid
   }
   pub fn computer_sid_mut(&mut self) -> &mut String {
      &mut self.computer_sid
   }
   
}


#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct UserRight {
   #[serde(rename = "Privilege")]
   privilege: String,
   #[serde(rename = "Results")]
   results: Vec<Member>,
   #[serde(rename = "LocalNames")]
   local_names: Vec<String>,
   #[serde(rename = "Collected", default = "default_true")]
   collected: bool,
   #[serde(rename = "FailureReason")]
   failure_reason: Option<String>,
}

impl UserRight {

   pub fn new() -> Self { 
      Self { 
         ..Default::default()
      }
   }


   pub fn privilege(&self) -> &String {
      &self.privilege
   }
   pub fn results(&self) -> &Vec<Member> {
      &self.results
   }
   pub fn local_names(&self) -> &Vec<String> {
      &self.local_names
   }
   pub fn collected(&self) -> &bool {
      &self.collected
   }
   pub fn failure_reason(&self) -> &Option<String> {
      &self.failure_reason
   }


   pub fn privilege_mut(&mut self) -> &mut String {
      &mut self.privilege
   }
   pub fn results_mut(&mut self) -> &mut Vec<Member> {
      &mut self.results
   }
   pub fn local_names_mut(&mut self) -> &mut Vec<String> {
      &mut self.local_names
   }
   pub fn collected_mut(&mut self) -> &mut bool {
      &mut self.collected
   }
   pub fn failure_reason_mut(&mut self) -> &mut Option<String> {
      &mut self.failure_reason
   }
}



#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DCRegistryData {
   #[serde(rename = "CertificateMappingMethods")]
   certificate_mapping_methods: Option<RegistryData>,
   #[serde(rename = "StrongCertificateBindingEnforcement")]
   strong_certificate_binding_enforcement: Option<RegistryData>,
}

impl Default for DCRegistryData {
   fn default() -> DCRegistryData {
      DCRegistryData {
         certificate_mapping_methods: None,
         strong_certificate_binding_enforcement: None,
      }
   }
}


#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct RegistryData {
   #[serde(rename = "Value")]
   value: i8,
   #[serde(rename = "Collected", default = "default_true")]
   collected: bool,
   #[serde(rename = "FailureReason")]
   failure_reason: Option<String>,
}

impl RegistryData {

   pub fn new() -> Self { 
      Self {
         collected: true,
         ..Default::default()
      }
   }
}


pub fn default_true() -> bool {
   true
}


#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct Member {
   #[serde(rename = "ObjectIdentifier")]
   object_identifier: String,
   #[serde(rename = "ObjectType")]
   object_type: String,
}

impl Member {

    pub fn new() -> Self {
      Self { 
         object_identifier: "SID".to_string(),
         ..Default::default()
      }
   }


   pub fn object_identifier(&self) -> &String {
      &self.object_identifier
   }
   pub fn object_type(&self) -> &String {
      &self.object_type
   }


   pub fn object_identifier_mut(&mut self) -> &mut String {
      &mut self.object_identifier
   }
   pub fn object_type_mut(&mut self) -> &mut String {
      &mut self.object_type
   }
}


#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AceTemplate {
   #[serde(rename = "PrincipalSID")]
   principal_sid: String,
   #[serde(rename = "PrincipalType")]
   principal_type: String,
   #[serde(rename = "RightName")]
   right_name: String,
   #[serde(rename = "IsInherited")]
   is_inherited: bool,
   #[serde(rename = "InheritanceHash")]
   inheritance_hash: String,
}

impl AceTemplate {

   pub fn new(
      principal_sid: String,
      principal_type: String,
      right_name: String,
      is_inherited: bool,
      inheritance_hash: String,
   ) -> Self { 
      Self { principal_sid, principal_type , right_name, is_inherited, inheritance_hash} 
   }


   pub fn principal_sid(&self) -> &String {
      &self.principal_sid
   }
   pub fn principal_type(&self) -> &String {
      &self.principal_type
   }
   pub fn right_name(&self) -> &String {
      &self.right_name
   }
   pub fn is_inherited(&self) -> &bool {
      &self.is_inherited
   }
   pub fn inheritance_hash(&self) -> &String {
      &self.inheritance_hash
   }


   pub fn principal_sid_mut(&mut self) -> &mut String {
      &mut self.principal_sid
   }
   pub fn principal_type_mut(&mut self) -> &mut String {
      &mut self.principal_type
   }
   pub fn right_name_mut(&mut self) -> &mut String {
      &mut self.right_name
   }
   pub fn is_inherited_mut(&mut self) -> &mut bool {
      &mut self.is_inherited
   }
   pub fn inheritance_hash_mut(&mut self) -> &mut String {
      &mut self.inheritance_hash
   }
}


#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Link {
   #[serde(rename = "IsEnforced")]
   is_enforced: bool,
   #[serde(rename = "GUID")]
   guid: String,
}

impl Link {

   pub fn new(is_enforced: bool, guid: String) -> Self { Self { is_enforced, guid } }
   

   pub fn is_enforced(&self) -> &bool {
      &self.is_enforced
   }
   pub fn guid(&self) -> &String {
      &self.guid
   }
 

   pub fn is_enforced_mut(&mut self) -> &mut bool {
      &mut self.is_enforced
   }
   pub fn guid_mut(&mut self) -> &mut String {
      &mut self.guid
   }
}


#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct GPOChange {
   #[serde(rename = "LocalAdmins")]
   local_admins: Vec<Member>,
   #[serde(rename = "RemoteDesktopUsers")]
   remote_desktop_users: Vec<Member>,
   #[serde(rename = "DcomUsers")]
   dcom_users: Vec<Member>,
   #[serde(rename = "PSRemoteUsers")]
   psremote_users: Vec<Member>,
   #[serde(rename = "AffectedComputers")]
   affected_computers: Vec<Member>,
}

impl GPOChange {

   pub fn new() -> Self { 
      Self {
         ..Default::default()
      } 
   }


   pub fn local_admins(&self) -> &Vec<Member> {
      &self.local_admins
   }
   pub fn remote_desktop_users(&self) -> &Vec<Member> {
      &self.remote_desktop_users
   }
   pub fn dcom_users(&self) -> &Vec<Member> {
      &self.dcom_users
   }
   pub fn psremote_users(&self) -> &Vec<Member> {
      &self.psremote_users
   }
   pub fn affected_computers(&self) -> &Vec<Member> {
      &self.affected_computers
   }


   pub fn local_admins_mut(&mut self) -> &mut Vec<Member> {
      &mut self.local_admins
   }
   pub fn remote_desktop_users_mut(&mut self) -> &mut Vec<Member> {
      &mut self.remote_desktop_users
   }
   pub fn dcom_users_mut(&mut self) -> &mut Vec<Member> {
      &mut self.dcom_users
   }
   pub fn psremote_users_mut(&mut self) -> &mut Vec<Member> {
      &mut self.psremote_users
   }
   pub fn affected_computers_mut(&mut self) -> &mut Vec<Member> {
      &mut self.affected_computers
   }
}


#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SPNTarget {
   #[serde(rename = "ComputerSID")]
   computer_sid: String,
   #[serde(rename = "Port")]
   port: i32,
   #[serde(rename = "Service")]
   service: String,
}

impl SPNTarget {

   pub fn new() -> Self { 
      Self { 
         computer_sid: "SID".to_string(), 
         port: 1433, 
         service: "SQLAdmin".to_string()
      } 
   }


   pub fn computer_sid(&self) -> &String {
      &self.computer_sid
   }
   pub fn port(&self) -> &i32 {
      &self.port
   }
   pub fn service(&self) -> &String {
      &self.service
   }


   pub fn computer_sid_mut(&mut self) -> &mut String {
      &mut self.computer_sid
   }
   pub fn port_mut(&mut self) -> &mut i32 {
      &mut self.port
   }
   pub fn service_mut(&mut self) -> &mut String {
      &mut self.service
   }
}


#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct FinalJson{
   data: Vec<Value>,
   meta: Meta,
}

impl FinalJson  {

   pub fn new(data: Vec<Value>, meta: Meta) -> Self { 
      Self {
         data,
         meta
      }
   }

   pub fn data(&self) -> &Vec<Value> {
      &self.data
   }
   pub fn meta(&self) -> &Meta {
      &self.meta
   }


   pub fn data_mut(&mut self) -> &mut Vec<Value> {
      &mut self.data
   }
   pub fn meta_mut(&mut self) -> &mut Meta {
      &mut self.meta
   }
}


#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct Meta {
   methods: i32,
   #[serde(rename = "type")]
   mtype: String,
   count: i32,
   version: i8,
   collectorversion: String
}

impl Meta {

   pub fn new(
      methods: i32,
      mtype: String,
      count: i32,
      version: i8,
      collectorversion: String
   ) -> Self { 
      Self { 
         methods,
         mtype,
         count,
         version,
         collectorversion
      } 
   }
   

   pub fn methods(&self) -> &i32 {
      &self.methods
   }
   pub fn mtype(&self) -> &String {
      &self.mtype
   }
   pub fn count(&self) -> &i32 {
      &self.count
   }
   pub fn version(&self) -> &i8 {
      &self.version
   }


   pub fn methods_mut(&mut self) -> &mut i32 {
      &mut self.methods
   }
   pub fn mtype_mut(&mut self) -> &mut String {
      &mut self.mtype
   }
   pub fn count_mut(&mut self) -> &mut i32 {
      &mut self.count
   }
   pub fn version_mut(&mut self) -> &mut i8 {
      &mut self.version
   }
}



pub fn parse_unknown(result: SearchEntry, _domain: &str) -> serde_json::value::Value  {

   let _result_dn = result.dn.to_uppercase();
   let _result_attrs: HashMap<String, Vec<String>> = result.attrs;
   let _result_bin: HashMap<String, Vec<Vec<u8>>> = result.bin_attrs;
   
   let unknown_json = json!({
       "unknown": null,
   });


   trace!("Parse Unknown object: {}", _result_dn);








   unknown_json
}