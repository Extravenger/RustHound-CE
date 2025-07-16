












use crate::banner::progress_bar;
use crate::storage::Storage;
use crate::utils::format::domain_to_dc;

use colored::Colorize;
use indicatif::ProgressBar;
use ldap3::adapters::{Adapter, EntriesOnly};
use ldap3::{adapters::PagedResults, controls::RawControl, LdapConnAsync, LdapConnSettings};
use ldap3::{Scope, SearchEntry};
use log::{info, debug, error, trace};
use std::io::{self, Write, stdin};
use std::collections::HashMap;
use std::error::Error;
use std::process;


#[allow(clippy::too_many_arguments)]
pub async fn ldap_search<S: Storage<LdapSearchEntry>>(
    ldaps: bool,
    ip: Option<&str>,
    port: Option<u16>,
    domain: &str,
    ldapfqdn: &str,
    username: Option<&str>,
    password: Option<&str>,
    kerberos: bool,
    ldapfilter: &str,
    storage: &mut S,
) -> Result<usize, Box<dyn Error>> {

    let ldap_args = ldap_constructor(
        ldaps, ip, port, domain, ldapfqdn, username, password, kerberos,
    )?;


    let consettings = LdapConnSettings::new()
        .set_conn_timeout(std::time::Duration::from_secs(10))
        .set_no_tls_verify(true);
    let (conn, mut ldap) = LdapConnAsync::with_settings(consettings, &ldap_args.s_url).await?;
    ldap3::drive!(conn);

    if !kerberos {
        debug!("Trying to connect with simple_bind() function (username:password)");
        let res = ldap
            .simple_bind(&ldap_args.s_username, &ldap_args.s_password)
            .await?
            .success();
        match res {
            Ok(_res) => {
                info!(
                    "Connected to {} Active Directory!",
                    domain.to_uppercase().bold().green()
                );
                info!("Starting data collection...");
            }
            Err(err) => {
                error!(
                    "Failed to authenticate to {} Active Directory. Reason: {err}\n",
                    domain.to_uppercase().bold().red()
                );
                process::exit(0x0100);
            }
        }
    } else {
        debug!("Trying to connect with sasl_gssapi_bind() function (kerberos session)");
        if !&ldapfqdn.contains("not set") {
            #[cfg(not(feature = "nogssapi"))]
            gssapi_connection(&mut ldap, &ldapfqdn, &domain).await?;
            #[cfg(feature = "nogssapi")]
            {
                error!("Kerberos auth and GSSAPI not compatible with current os!");
                process::exit(0x0100);
            }
        } else {
            error!(
                "Need Domain Controller FQDN to bind GSSAPI connection. Please use '{}'\n",
                "-f DC01.DOMAIN.LAB".bold()
            );
            process::exit(0x0100);
        }
    }


    let mut total = 0; // for progress bar


    let res = match get_all_naming_contexts(&mut ldap).await {
        Ok(res) => {
            trace!("naming_contexts: {:?}", &res);
            res
        }
        Err(err) => {
            error!("No namingContexts found! Reason: {err}\n");
            process::exit(0x0100);
        }
    };



    if res.iter().any(|s| s.contains("Configuration")) {
        for cn in &res {


            let ctrls = RawControl {
                ctype: String::from("1.2.840.113556.1.4.801"),
                crit: true,
                val: Some(vec![48, 3, 2, 1, 5]),
            };
            ldap.with_controls(ctrls.to_owned());










            info!("Ldap filter : {}", ldapfilter.bold().green());
            let _s_filter = ldapfilter;


            let adapters: Vec<Box<dyn Adapter<_, _>>> = vec![
                Box::new(EntriesOnly::new()),
                Box::new(PagedResults::new(999)),
            ];


            let mut search = ldap
                .streaming_search_with(
                    adapters, // Adapter which fetches Search results with a Paged Results control.
                    cn,
                    Scope::Subtree,
                    _s_filter,
                    vec!["*", "nTSecurityDescriptor"],


                )
                .await?;


            let pb = ProgressBar::new(1);
            let mut count = 0;
            while let Some(entry) = search.next().await? {
                let entry = SearchEntry::construct(entry);

                total += 1;

                count += 1;
                progress_bar(
                    pb.to_owned(),
                    "LDAP objects retrieved".to_string(),
                    count,
                    "#".to_string(),
                );

                storage.add(entry.into())?;
            }
            pb.finish_and_clear();

            let res = search.finish().await.success();
            match res {
                Ok(_res) => info!("All data collected for NamingContext {}", &cn.bold()),
                Err(err) => {
                    error!("No data collected on {}! Reason: {err}", &cn.bold().red());
                }
            }
        }





        ldap.unbind().await?;
    }




    drop(ldap);
    if total == 0 {
        error!("No LDAP objects found! Exiting...");

        process::exit(0x0100);
    }

    storage.flush()?;



    Ok(total)
}


struct LdapArgs {
    s_url: String,
    _s_dc: Vec<String>,
    _s_email: String,
    s_username: String,
    s_password: String,
}


fn ldap_constructor(
    ldaps: bool,
    ip: Option<&str>,
    port: Option<u16>,
    domain: &str,
    ldapfqdn: &str,
    username: Option<&str>,
    password: Option<&str>,
    kerberos: bool,
) -> Result<LdapArgs, Box<dyn Error>> {

    let s_url = prepare_ldap_url(ldaps, ip, port, domain);


    let s_dc = prepare_ldap_dc(domain);


    let mut s = String::new();
    let mut _s_username: String;
    if username.is_none() && !kerberos {
        print!("Username: ");
        io::stdout().flush()?;
        stdin()
            .read_line(&mut s)
            .expect("Did not enter a correct username");
        io::stdout().flush()?;
        if let Some('\n') = s.chars().next_back() {
            s.pop();
        }
        if let Some('\r') = s.chars().next_back() {
            s.pop();
        }
        _s_username = s.to_owned();
    } else {
        _s_username = username.unwrap_or("not set").to_owned();
    }


    let mut s_email: String = "".to_owned();
    if !_s_username.contains("@") {
        s_email.push_str(&_s_username.to_string());
        s_email.push_str("@");
        s_email.push_str(domain);
        _s_username = s_email.to_string();
    } else {
        s_email = _s_username.to_string().to_lowercase();
    }


    let mut _s_password: String = String::new();
    if !_s_username.contains("not set") && !kerberos {
        _s_password = match password {
            Some(p) => p.to_owned(),
            None => rpassword::prompt_password("Password: ").unwrap_or("not set".to_string()),
        };
    } else {
        _s_password = password.unwrap_or("not set").to_owned();
    }


    debug!("IP: {}", match ip {
        Some(ip) => ip,
        None => "not set"
    });
    debug!("PORT: {}", match port {
        Some(p) => {
            p.to_string()
        },
        None => "not set".to_owned()
    });
    debug!("FQDN: {}", ldapfqdn);
    debug!("Url: {}", s_url);
    debug!("Domain: {}", domain);
    debug!("Username: {}", _s_username);
    debug!("Email: {}", s_email.to_lowercase());
    debug!("Password: {}", _s_password);
    debug!("DC: {:?}", s_dc);
    debug!("Kerberos: {:?}", kerberos);

    Ok(LdapArgs {
        s_url: s_url.to_string(),
        _s_dc: s_dc,
        _s_email: s_email.to_string().to_lowercase(),
        s_username: s_email.to_string().to_lowercase(),
        s_password: _s_password.to_string(),
    })
}


fn prepare_ldap_url(
    ldaps: bool,
    ip: Option<&str>,
    port: Option<u16>,
    domain: &str
) -> String {
    let protocol = if ldaps || port.unwrap_or(0) == 636 {
        "ldaps"
    } else {
        "ldap"
    };

    let target = match ip {
        Some(ip) => ip,
        None => domain,
    };

    match port {
        Some(port) => {
            format!("{protocol}://{target}:{port}")
        }
        None => {
            format!("{protocol}://{target}")
        }
    }
}


pub fn prepare_ldap_dc(domain: &str) -> Vec<String> {

    let mut dc: String = "".to_owned();
    let mut naming_context: Vec<String> = Vec::new();


    if !domain.contains(".") {
        dc.push_str("DC=");
        dc.push_str(domain);
        naming_context.push(dc[..].to_string());
    }
    else {
        naming_context.push(domain_to_dc(domain));
    }


    naming_context.push(format!("{}{}", "CN=Configuration,", &dc[..])); 
    naming_context
}


#[cfg(not(feature = "nogssapi"))]
async fn gssapi_connection(
    ldap: &mut ldap3::Ldap,
    ldapfqdn: &str,
    domain: &str,
) -> Result<(), Box<dyn Error>> {
    let res = ldap.sasl_gssapi_bind(ldapfqdn).await?.success();
    match res {
        Ok(_res) => {
            info!("Connected to {} Active Directory!", domain.to_uppercase().bold().green());
            info!("Starting data collection...");
        }
        Err(err) => {
            error!("Failed to authenticate to {} Active Directory. Reason: {err}\n", domain.to_uppercase().bold().red());
            process::exit(0x0100);
        }
    }
    Ok(())
}


pub async fn get_all_naming_contexts(
    ldap: &mut ldap3::Ldap
) -> Result<Vec<String>, Box<dyn Error>> {

    let adapters: Vec<Box<dyn Adapter<_, _>>> = vec![
        Box::new(EntriesOnly::new()),
        Box::new(PagedResults::new(999)),
    ];


    let mut search = ldap.streaming_search_with(
        adapters,
        "", 
        Scope::Base,
        "(objectClass=*)",
        vec!["namingContexts"],
    ).await?;


    let mut rs: Vec<SearchEntry> = Vec::new();
    while let Some(entry) = search.next().await? {
        let entry = SearchEntry::construct(entry);
        rs.push(entry);
    }
    let res = search.finish().await.success();


    let mut naming_contexts: Vec<String> = Vec::new();
    match res {
        Ok(_res) => {
            debug!("All namingContexts collected!");
            for result in rs {
                let result_attrs: HashMap<String, Vec<String>> = result.attrs;

                for (_key, value) in &result_attrs {
                    for naming_context in value {
                        debug!("namingContext found: {}",&naming_context.bold().green());
                        naming_contexts.push(naming_context.to_string());
                    }
                }
            }
            return Ok(naming_contexts)
        }
        Err(err) => {
            error!("No namingContexts found! Reason: {err}");
        }
    }

    Ok(Vec::new())
}


#[derive(Debug, Clone, bincode::Encode, bincode::Decode)]
pub struct LdapSearchEntry {

    pub dn: String,

    pub attrs: HashMap<String, Vec<String>>,

    pub bin_attrs: HashMap<String, Vec<Vec<u8>>>,
}

impl From<SearchEntry> for LdapSearchEntry {
    fn from(entry: SearchEntry) -> Self {
        LdapSearchEntry {
            dn: entry.dn,
            attrs: entry.attrs,
            bin_attrs: entry.bin_attrs,
        }
    }
}

impl From<LdapSearchEntry> for SearchEntry {
    fn from(entry: LdapSearchEntry) -> Self {
        SearchEntry {
            dn: entry.dn,
            attrs: entry.attrs,
            bin_attrs: entry.bin_attrs,
        }
    }
}
