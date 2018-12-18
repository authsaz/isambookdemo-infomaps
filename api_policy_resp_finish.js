importClass(Packages.com.tivoli.am.fim.trustserver.sts.utilities.IDMappingExtUtils);
importMappingRule("api_policy_config");

var param_target = context.get(Scope.SESSION,"urn:authsaz:resp","target");
var param_challenge = context.get(Scope.SESSION,"urn:authsaz:resp","challenge");
var param_username = context.get(Scope.SESSION,"urn:ibm:security:asf:response:token:attributes","username");

var response = solve_challenge_get_response(param_challenge);
var target_url = param_target + "?response=" + response;

context.set(Scope.SESSION, "urn:ibm:security:asf:response:token:attributes", "itfim_override_targeturl_attr", target_url);
success.setValue(true);
