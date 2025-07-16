use once_cell::sync::Lazy;
use regex::Regex;




pub static GPLINK_RE1: Lazy<Regex> = Lazy::new(|| Regex::new(r"[a-zA-Z0-9-]{36}").unwrap());
pub static GPLINK_RE2: Lazy<Regex> = Lazy::new(|| Regex::new(r"[;][0-4]{1}").unwrap());


pub static COMMON_RE1: Lazy<Regex> = Lazy::new(|| Regex::new(r"^S-[0-9]+-[0-9]+-[0-9]+(?:-[0-9]+)+").unwrap());


pub static PARSER_MOD_RE1: Lazy<Regex> = Lazy::new(|| Regex::new(r"[0-9a-z-A-Z]{1,}-[0-9a-z-A-Z]{1,}-[0-9a-z-A-Z]{1,}-[0-9a-z-A-Z]{1,}").unwrap());
pub static PARSER_MOD_RE2: Lazy<Regex> = Lazy::new(|| Regex::new(r"CN=DOMAINUPDATES,CN=SYSTEM,").unwrap());


pub static OBJECT_SID_RE1: Lazy<Regex> = Lazy::new(|| Regex::new(r"^S-[0-9]{1}-[0-9]{1}-[0-9]{1,}-[0-9]{1,}-[0-9]{1,}-[0-9]{1,}").unwrap());
pub static SID_PART1_RE1: Lazy<Regex> = Lazy::new(|| Regex::new(r"S-.*-").unwrap());


pub static IS_SID_RE1: Lazy<Regex> = Lazy::new(|| Regex::new(r".*S-1-5.*").unwrap());