importClass(Packages.java.util.UUID);
importPackage(com.ibm.security.access.httpclient);

function init_challnege(variables){
    var uuid = UUID.randomUUID().toString();
    var nowtime = Math.floor(new Date().getTime() / 1000);
    var data = {
         iat: nowtime,
         exp: Math.floor((nowtime + (1 * expiresInSeconds * 1000)) / 1000),
         sub: variables.username,
         policy: variables.resp_policy,
         isAuth: false
    }  
    context.set(Scope.SESSION,"urn:authsaz:ref","uuid",uuid);
    doPost(conf.webservice, {action: 'save', uuid: ""+ uuid, data: data});
    return uuid;
}

function verify_response(variables){
    var uuid = context.get(Scope.SESSION,"urn:authsaz:ref","uuid");
    if(uuid == variables.param_response){
        var json = doPost(conf.webservice, {action: 'load', uuid: ""+ uuid});
        if(json.data.isAuth){
            context.set(Scope.SESSION,"urn:authsaz:ref","uuid",""); // invalidate uuid
            return true;
        }
    }
    return false;
}

function load_data_from_challenge(token){
    var json = doPost(conf.webservice, {action: 'load', uuid: "" + token});
    return json.data;
}

function solve_challenge_get_response(token){
    var json = doPost(conf.webservice, {action: 'load', uuid: "" + token});
    json["isAuth"] = true;
    doPost(conf.webservice, {action: 'save', uuid: ""+ token, data: json});
    return token;
}

function doPost(url,data){
    var headers = new com.ibm.security.access.httpclient.Headers();
    headers.addHeader("Accept", "application/json");
    headers.addHeader("Content-type", "application/json");
    var httpRequestBodyJSON =  JSON.stringify(data);
    var response =com.ibm.security.access.httpclient.HttpClient.httpPost(url, headers, httpRequestBodyJSON, null, null, null, null, null);
     
    if (response != null){
       var jsonResponseString = response.getBody();
       var jsonResponseObj = JSON.parse(jsonResponseString);
       return jsonResponseObj;
    }
    return {};
}
