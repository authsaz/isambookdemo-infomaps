importClass(Packages.com.tivoli.am.fim.trustserver.sts.utilities.IDMappingExtUtils);
importMappingRule("api_policy_config");

IDMappingExtUtils.traceString("api_policy_init STARTED");

function get_resp_policy(){
   /*
   /* The name of 1st policy should be finish with "_init"  
   /* The name of 2nd policy should be finish with "_resp"
   */

   var resp_policy = "urn:unknown";
   var this_policy = context.get(Scope.SESSION,"urn:ibm:security:asf:policy","policyID");

   if(this_policy.endsWith("_init")){
      resp_policy = this_policy.substring(0,this_policy.length()-5) + "_resp";
   }
   return resp_policy;
}

function step_challenge(variables){
    var token = init_challnege(variables);
    // template address: /authsvc/authenticator/authsaz/initiate_api_policy.json
    macros.put("@POLICY_ID@",variables.resp_policy);
    macros.put("@CHALLENGE@",token);
    success.setValue(false);
}

function step_response(variables){
    if(verify_response(variables)){
        success.setValue(true);
    }else{
        step_challenge(variables);
    }
}

function step_abort(variables){
    success.endPolicyWithoutCredential();
}

param_response = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter","response")
var variables = {
   username: "" +context.get(Scope.SESSION,"urn:ibm:security:asf:response:token:attributes","username"),
   param_response: "" + param_response,
   resp_policy: "" + get_resp_policy(),
   conf: conf
};

IDMappingExtUtils.traceString("api_policy_init: " + JSON.stringify(variables));

if(variables.username == null || variables.username==""){
    step_abort(variables);
}else{
    if(param_response != null && param_response !=""){
        step_response(variables);
    }else{
        step_challenge(variables);
    }
}