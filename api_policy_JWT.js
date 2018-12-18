importClass(Packages.java.util.UUID);
importMappingRule("jsrsasign");

function init_challnege(variables){
    var uuid = UUID.randomUUID().toString();
    var nowtime = Math.floor(new Date().getTime() / 1000);
    var data = {
         iat: nowtime,
         exp: nowtime + expiresInSeconds,
         sub: variables.username,
         policy: variables.resp_policy,
         isAuth: false,
         uuid: ""+uuid
    }
    context.set(Scope.SESSION,"urn:authsaz:ref","uuid",uuid);
    return makeJWT(data);
}

function verify_response(variables){
    var uuid = context.get(Scope.SESSION,"urn:authsaz:ref","uuid");
    var sJWT = variables.param_response;    
    var payloadObj = decodeJWT(sJWT);
    if(payloadObj.isAuth && uuid == payloadObj.uuid){
        context.set(Scope.SESSION,"urn:authsaz:ref","uuid",""); // invalidate uuid
        return true;
    }
    return false;
}

function load_data_from_challenge(challenge){
    return decodeJWT(challenge);
}

function solve_challenge_get_response(sJWT){
    var claims = decodeJWT(sJWT)
    if(claims == {}){
        return false;
    }
    claims["isAuth"] = true;
    return makeJWT(claims);
}

function makeJWT(claims){
    var oHeader = {alg: 'HS256', typ: 'JWT'};
    var sHeader = JSON.stringify(oHeader);
    var sPayload = JSON.stringify(claims);
    return KJUR.jws.JWS.sign("HS256", sHeader, sPayload, toHex(conf.secret));
}

function verifyJWT(token){
    var sJWT = "" + token;
    return KJUR.jws.JWS.verifyJWT(sJWT, toHex(conf.secret), {alg: ['HS256'] });
}

function decodeJWT(token){
    if(verifyJWT(token)){
        var sJWT = "" + token;
        var payloadObj = KJUR.jws.JWS.readSafeJSONString(b64utoutf8(sJWT.split(".")[1]));
        return payloadObj;
    }else{
        return {};
    }
}

function toHex(str) {
	var hex = '';
	for(var i=0;i<str.length;i++) {
		hex += ''+str.charCodeAt(i).toString(16);
	}
	return hex;
}