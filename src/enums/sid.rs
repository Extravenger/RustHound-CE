use std::error::Error;
use log::{trace,error};
use crate::enums::{secdesc::LdapSid, regex::IS_SID_RE1};


pub fn is_sid(input: &str) -> Result<bool, Box<dyn Error>> {
    Ok(IS_SID_RE1.is_match(input))
}


pub fn sid_maker(sid: LdapSid, domain: &str) -> String {
    trace!("sid_maker before: {:?}",&sid);

    let sub = sid.sub_authority.iter().map(|x| x.to_string()).collect::<Vec<String>>().join("-");

    let result = format!("S-{}-{}-{}", sid.revision, sid.identifier_authority.value[5], sub);

    let final_sid = {
        if result.len() <= 16 {
            format!("{}-{}", domain.to_uppercase(), result.to_owned())
        } else {
            result
        }
    };

    trace!("sid_maker value: {}",final_sid);
    if final_sid.contains("S-0-0"){
        error!("SID contains null bytes!\n[INPUT: {:?}]\n[OUTPUT: {}]", &sid, final_sid);
    }

    final_sid
}


pub fn objectsid_to_vec8(sid: &str) -> Vec<u8>
{
    sid.as_bytes().iter().map(|x| *x).collect::<Vec<u8>>()
}




pub fn _decode_guid(raw_guid: &[u8]) -> String
{


    let raw_guid = raw_guid.iter().map(|x| x & 0xFF).collect::<Vec<u8>>();
    let rev = | x: &[u8] | -> Vec<u8> { x.iter().map(|i| *i).rev().collect::<Vec<u8>>()};


    let str_guid = format!(
        "{}-{}-{}-{}-{}",
        &hex_push(&raw_guid[0..4]),
        &hex_push(&rev(&raw_guid[4..6])),
        &hex_push(&rev(&raw_guid[6..8])),
        &hex_push(&raw_guid[8..10]),
        &hex_push(&raw_guid[10..16]),
    );

    str_guid
}



pub fn hex_push(blob: &[u8]) -> String {

    blob.iter().map(|x| format!("{:X}", x)).collect::<String>()
}


pub fn bin_to_string(raw_guid: &[u8]) -> String
{





    let raw_guid = raw_guid.iter().map(|x| x & 0xFF).collect::<Vec<u8>>();
    let rev = | x: &[u8] | -> Vec<u8> { x.iter().map(|i| *i).collect::<Vec<u8>>()};

    let str_guid = format!(
        "{}-{}-{}-{}-{}",
        &hex_push(&raw_guid[12..16]),
        &hex_push(&raw_guid[10..12]),
        &hex_push(&raw_guid[8..10]),
        &hex_push(&rev(&raw_guid[6..8])),
        &hex_push(&rev(&raw_guid[0..6]))
    );

    str_guid  
}


pub fn decode_guid_le(raw_guid: &[u8]) -> String {

    let str_guid = format!(
        "{:02X}{:02X}{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
        raw_guid[3], raw_guid[2], raw_guid[1], raw_guid[0], // Data1 (little-endian)
        raw_guid[5], raw_guid[4],                           // Data2 (little-endian)
        raw_guid[7], raw_guid[6],                           // Data3 (little-endian)
        raw_guid[8], raw_guid[9],                           // Data4 (big-endian)
        raw_guid[10], raw_guid[11], raw_guid[12], raw_guid[13], raw_guid[14], raw_guid[15] // Data5 (big-endian)
    );

    str_guid
}