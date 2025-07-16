use chrono::{NaiveDateTime, Local};
use std::convert::TryInto;
use std::error::Error;




pub fn convert_timestamp(timestamp: i64) -> i64
{
    let offset: i64 = 134774*24*60*60;
    let epoch: i64 = timestamp/10000000-offset;
    epoch
}


pub fn string_to_epoch(date: &str) -> Result<i64, Box<dyn Error>> {


    let str_representation = date.split('.').next().ok_or("Invalid date format")?;
    

    let naive_date = NaiveDateTime::parse_from_str(str_representation, "%Y%m%d%H%M%S")?;
    Ok(naive_date.and_utc().timestamp())
}



pub fn return_current_time() -> String
{
    Local::now().format("%T").to_string()
}


pub fn return_current_date() -> String
{
    Local::now().format("%D").to_string()
}


pub fn return_current_fulldate() -> String
{
    Local::now().format("%Y%m%d%H%M%S").to_string()
}


pub fn filetime_to_span(filetime: Vec<u8>) -> Result<i64, Box<dyn Error>> {
    if filetime.len() >= 8 {

        let span = i64::from_ne_bytes(filetime[0..8].try_into()?);
        return Ok(span);
    }
    Ok(0)
}


pub fn span_to_string(span: i64) -> String {

    let span_in_seconds = span / 10_000_000; // 1 second = 10^7 100-nanosecond units
    let span_abs = span_in_seconds.abs();

    if span_abs % 31536000 == 0 && span_abs / 31536000 >= 1 {
        if span_abs / 31536000 == 1 {
            "1 year".to_string()
        } else {
            format!("{} years", span_abs / 31536000)
        }
    } else if span_abs % 2592000 == 0 && span_abs / 2592000 >= 1 {
        if span_abs / 2592000 == 1 {
            "1 month".to_string()
        } else {
            format!("{} months", span_abs / 2592000)
        }
    } else if span_abs % 604800 == 0 && span_abs / 604800 >= 1 {
        if span_abs / 604800 == 1 {
            "1 week".to_string()
        } else {
            format!("{} weeks", span_abs / 604800)
        }
    } else if span_abs % 86400 == 0 && span_abs / 86400 >= 1 {
        if span_abs / 86400 == 1 {
            "1 day".to_string()
        } else {
            format!("{} days", span_abs / 86400)
        }
    } else if span_abs % 3600 == 0 && span_abs / 3600 >= 1 {
        if span_abs / 3600 == 1 {
            "1 hour".to_string()
        } else {
            format!("{} hours", span_abs / 3600)
        }
    } else if span_abs % 60 == 0 && span_abs / 60 >= 1 {
        if span_abs / 60 == 1 {
            "1 minute".to_string()
        } else {
            format!("{} minutes", span_abs / 60)
        }
    } else {
        "less than a minute".to_string()
    }
}