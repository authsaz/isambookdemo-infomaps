importClass(Packages.com.tivoli.am.fim.trustserver.sts.utilities.IDMappingExtUtils);
importMappingRule("api_policy_config");

var param_challenge = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter","challenge");
var param_target = context.get(Scope.REQUEST,"urn:ibm:security:asf:request:parameter","callback");
var data = load_data_from_challenge(param_challenge);
var username = data.sub;
var policy = data.policy;

var this_policy = "" + context.get(Scope.SESSION,"urn:ibm:security:asf:policy","policyID");

IDMappingExtUtils.traceString("api_policy_resp_init: " + username + "," + param_challenge  + "," + param_target + "," + policy + "," + this_policy);

if(this_policy != policy){
    success.endPolicyWithoutCredential();
}else{
    context.set(Scope.SESSION,"urn:ibm:security:asf:response:token:attributes","username",username);
    context.set(Scope.SESSION,"urn:authsaz:resp","challenge",param_challenge );
    context.set(Scope.SESSION,"urn:authsaz:resp","target", param_target);

    success.setValue(true);
}