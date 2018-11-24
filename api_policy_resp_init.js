importClass(Packages.com.tivoli.am.fim.trustserver.sts.utilities.IDMappingExtUtils);

var param_ref_id = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter","refid");
var username = IDMappingExtUtils.getIDMappingExtCache().get(param_ref_id);
var param_target = context.get(Scope.REQUEST,"urn:ibm:security:asf:request:parameter","callback");

IDMappingExtUtils.traceString("api_policy_resp_init: " + username + "," + param_ref_id + "," + param_target);

context.set(Scope.SESSION,"urn:ibm:security:asf:response:token:attributes","username",username);
context.set(Scope.SESSION,"urn:authsaz:resp","uuid",param_ref_id);
context.set(Scope.SESSION,"urn:authsaz:resp","target", param_target);

success.setValue(true);
