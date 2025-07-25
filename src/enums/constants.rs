pub const ACCESS_ALLOWED_ACE_TYPE: u8 = 0x00;
pub const ACCESS_DENIED_ACE_TYPE: u8 = 0x01;
pub const ACCESS_ALLOWED_OBJECT_ACE_TYPE: u8 = 0x05;
pub const ACCESS_DENIED_OBJECT_ACE_TYPE: u8 = 0x06;

pub const CONTAINER_INHERIT_ACE: u8 = 0x01;
pub const FAILED_ACCESS_ACE_FLAG: u8 = 0x80;
pub const INHERIT_ONLY_ACE: u8 = 0x08;
pub const INHERITED_ACE: u8 = 0x10;
pub const NO_PROPAGATE_INHERIT_ACE: u8 = 0x04;
pub const OBJECT_INHERIT_ACE: u8 = 0x01;
pub const SUCCESSFUL_ACCESS_ACE_FLAG: u8 = 0x04;

pub const ACE_OBJECT_TYPE_PRESENT: u32 = 0x0001;
pub const ACE_INHERITED_OBJECT_TYPE_PRESENT: u32 = 0x0002;


pub const GET_CHANGES: &str = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2";
pub const GET_CHANGES_ALL: &str = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2";
pub const GET_CHANGES_IN_FILTERED_SET: &str = "89e95b76-444d-4c62-991a-0facbeda640c";
pub const WRITE_MEMBER: &str = "bf9679c0-0de6-11d0-a285-00aa003049e2";
pub const USER_FORCE_CHANGE_PASSWORD: &str = "00299570-246d-11d0-a768-00aa006e0529";
pub const ALLOWED_TO_ACT: &str = "3f78c3e5-f79a-46bd-a0b8-9d18116ddc79";
pub const USER_ACCOUNT_RESTRICTIONS_SET: &str = "4c164200-20c0-11d0-a768-00aa006e0529";
pub const WRITE_GPLINK: &str = "f30e3bbe-9ff0-11d1-b603-0000f80367c1";
pub const WRITE_SPN: &str = "f3a64788-5306-11d1-a9c5-0000f80367c1";
pub const ADD_KEY_PRINCIPAL: &str = "5b47d60f-6090-40b2-9f37-2a4de88f3063";

pub const PKI_NAME_FLAG: &str = "ea1dddc4-60ff-416e-8cc0-17cee534bce7";
pub const PKI_ENROLLMENT_FLAG: &str = "d15ef7d8-f226-46db-ae79-b34e560bd12c";
pub const ENROLL: &str = "0e10c968-78fb-11d2-90d4-00c04f79dc55";
pub const AUTO_ENROLL: &str = "a05b8cc2-17bc-4802-a710-e7c15ab866a2";