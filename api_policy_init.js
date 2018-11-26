importClass(Packages.com.tivoli.am.fim.trustserver.sts.utilities.IDMappingExtUtils);
importClass(Packages.java.util.UUID);
importMappingRule("sha256");
importMappingRule("api_policy_config");

var policy = "urn:unknown";

var this_policy = context.get(Scope.SESSION,"urn:ibm:security:asf:policy","policyID");

if (this_policy.equals("urn:ibm:security:authentication:asf:api_policy_presence")){
   policy = "urn:ibm:security:authentication:asf:api_policy_presence_resp";
} else if (this_policy.equals("urn:ibm:security:authentication:asf:api_policy_otp_finger_init")) {
   policy = "urn:ibm:security:authentication:asf:api_policy_otp_finger_resp";
} else if (this_policy.equals("urn:ibm:security:authentication:asf:api_policy_otp_init")) {
   policy = "urn:ibm:security:authentication:asf:api_policy_otp_resp";
} else if (this_policy.equals("urn:ibm:security:authentication:asf:api_policy_presence_finger_init")) {
   policy = "urn:ibm:security:authentication:asf:api_policy_presence_finger_resp";
}


var username = context.get(Scope.SESSION,"urn:ibm:security:asf:response:token:attributes","username");
var param_ref_key = context.get(Scope.REQUEST, "urn:ibm:security:asf:request:parameter","ref_key");
var uuid = context.get(Scope.SESSION,"urn:authsaz:ref","uuid");


IDMappingExtUtils.traceString("api_policy_init: " + this_policy + "," + username + "," + param_ref_key + "," + uuid);

function step_initiate(){
    uuid = UUID.randomUUID().toString();
    var refferencekey = sha256(uuid + salt + username);
    context.set(Scope.SESSION,"urn:authsaz:ref","uuid",uuid);
    IDMappingExtUtils.getIDMappingExtCache().put(uuid,username,60); // using IDMappingExtCache is simplest way.
    // template address: /authsvc/authenticator/authsaz/initiate_api_policy.json
    macros.put("@POLICY_ID@",policy);
    macros.put("@REF_ID@",uuid);
    success.setValue(false);
}

function step_response(){
    var refferencekey = sha256(uuid + salt + username);
    if(param_ref_key ==refferencekey){
        success.setValue(true);
    }else{
        step_initiate();
    }
}

function step_abort(){
    success.endPolicyWithoutCredential();
}

if(username == null || username==""){
    step_abort();
}else{
    if(uuid != null && param_ref_key != null && uuid != "" && param_ref_key!=""){
        step_response();
    }else{
        step_initiate();
    }
}
