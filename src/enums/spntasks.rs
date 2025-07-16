use crate::objects::common::SPNTarget;




pub fn check_spn(serviceprincipalname: &str) -> Option<SPNTarget>
{
   if serviceprincipalname.to_lowercase().contains("mssqlsvc")
   {
      let mut mssqlsvc_spn = SPNTarget::new();


      if serviceprincipalname.to_lowercase().contains(":")
      {
         let split = serviceprincipalname.split(":");
         let vec = split.collect::<Vec<&str>>();
         let mut fqdn = vec[0].to_owned();
         let value = vec[1].to_owned();


         let port = value.parse::<i32>().unwrap_or(1433);



         let split = fqdn.split("/");
         let vec = split.collect::<Vec<&str>>();
         fqdn = vec[1].to_owned().to_uppercase();


         *mssqlsvc_spn.computer_sid_mut() = fqdn;
         *mssqlsvc_spn.port_mut() = port;
      }
      else
      {


         let split = serviceprincipalname.split("/");
         let vec = split.collect::<Vec<&str>>();
         let fqdn = vec[1].to_owned().to_uppercase();
         let port = 1433;
 

         *mssqlsvc_spn.computer_sid_mut() = fqdn;
         *mssqlsvc_spn.port_mut() = port;
      }
      Some(mssqlsvc_spn)
   }
   else {
      None
   }
}