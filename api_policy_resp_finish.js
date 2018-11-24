importMappingRule("sha256");
importMappingRule("api_policy_config");

var param_target = context.get(Scope.SESSION,"urn:authsaz:resp","target");
var param_uuid = context.get(Scope.SESSION,"urn:authsaz:resp","uuid");
var param_username = context.get(Scope.SESSION,"urn:ibm:security:asf:response:token:attributes","username");
var refferencekey = sha256(param_uuid + salt + param_username);

var target_url = param_target + "?refferencekey=" + refferencekey;

//var targetUrlAttr = new Attribute("itfim_override_targeturl_attr", "urn:ibm:names:ITFIM:5.1:accessmanager", target_url);
//stsuu.addAttribute(targetUrlAttr);

context.set(Scope.SESSION, "urn:ibm:security:asf:response:token:attributes", "itfim_override_targeturl_attr", target_url);
success.setValue(true);