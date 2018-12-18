importClass(Packages.java.util.UUID);
importPackage(Packages.com.tivoli.am.fim.trustserver.sts);
importPackage(Packages.com.tivoli.am.fim.trustserver.sts.uuser);
importPackage(Packages.com.ibm.security.access.user);
importClass(Packages.com.tivoli.am.fim.trustserver.sts.utilities.IDMappingExtUtils);
importClass(Packages.java.util.ArrayList);
importClass(Packages.java.util.HashMap);
importClass(Packages.java.lang.System);
importClass(Packages.com.tivoli.am.fim.fedmgr2.trust.util.LocalSTSClient);

function init_challnege(variables){
    var uuid = UUID.randomUUID().toString();
    var nowtime = Math.floor(new Date().getTime() / 1000);
    var data = {
         iat: nowtime,
         exp: nowtime + expiresInSeconds,
         sub: variables.username,
         policy: variables.resp_policy,
         isAuth: false,
         uuid: "" + uuid
    }
    context.set(Scope.SESSION,"urn:authsaz:ref","uuid",uuid);
    var sJWT = buildJwtAccessToken(data);
    return sJWT;
}

function verify_response(variables){
    var uuid = context.get(Scope.SESSION,"urn:authsaz:ref","uuid");
    var sJWT = variables.param_response;
    var tokenStsuu = validateJwt(sJWT);
    var isAuth = Boolean(tokenStsuu.getAttributeContainer().getAttributeByName("isAuth").getValues()[0]);
    var param_uuid = tokenStsuu.getAttributeContainer().getAttributeByName("uuid").getValues()[0];
    if(isAuth && uuid == param_uuid){
        context.set(Scope.SESSION,"urn:authsaz:ref","uuid",""); // invalidate uuid
        return true;
    }
    return false;
}

function load_data_from_challenge(token){
    var tokenStsuu = validateJwt(token);
    claims = {
        iat: Number(tokenStsuu.getAttributeContainer().getAttributeByName("iat").getValues()[0]),
        exp: Number(tokenStsuu.getAttributeContainer().getAttributeByName("exp").getValues()[0]),
        sub: "" + tokenStsuu.getAttributeContainer().getAttributeByName("sub").getValues()[0],
        policy: "" + tokenStsuu.getAttributeContainer().getAttributeByName("policy").getValues()[0],
        isAuth: Boolean(tokenStsuu.getAttributeContainer().getAttributeByName("isAuth").getValues()[0]),
        uuid: "" + tokenStsuu.getAttributeContainer().getAttributeByName("uuid").getValues()[0]
    }
    return claims;
}

function solve_challenge_get_response(sJWT){
    var tokenStsuu = validateJwt(sJWT);
    claims = {
        iat: Number(tokenStsuu.getAttributeContainer().getAttributeByName("iat").getValues()[0]),
        exp: Number(tokenStsuu.getAttributeContainer().getAttributeByName("exp").getValues()[0]),
        sub: "" + tokenStsuu.getAttributeContainer().getAttributeByName("sub").getValues()[0],
        policy: "" + tokenStsuu.getAttributeContainer().getAttributeByName("policy").getValues()[0],
        isAuth: true,
        uuid: "" + tokenStsuu.getAttributeContainer().getAttributeByName("uuid").getValues()[0]
    }
    var sJWT = buildJwtAccessToken(claims);
    return sJWT;
}

// https://www.ibm.com/blogs/security-identity-access/oauth-jwt-access-token/
// https://ibm.ent.box.com/s/da6r4ev5xt25widzc6rbll1p5cu40mft/file/305417714729

function trace(msg) {
	IDMappingExtUtils.traceString("\n\nJWT AT:\n" + msg + "\n");
}

function callSts(baseToken, identifier) {
	// We used the  validate request type
	var requestType = "http://schemas.xmlsoap.org/ws/2005/02/trust/Validate";
	// We don't have any claims to pass. 
	var tokenResult = LocalSTSClient.doRequest(requestType, identifier, identifier, baseToken, null);

	return tokenResult;
}

function validateJwt(at) {

	// First we need to build a binary security token from the jwt:
	var bst = IDMappingExtUtils.stringToXMLElement('<wss:BinarySecurityToken xmlns:wss="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" wss:EncodingType="http://ibm.com/2004/01/itfim/base64encode"  wss:ValueType="urn:com:ibm:JWT" >'+at+'</wss:BinarySecurityToken>')

	// validate the token
	var token = callSts(bst, "urn:jwt:validate");

	// Token is valid. Parse it as an stsuu
	var tokenStsuu = new STSUniversalUser();

	if(token.errorMessage != null) {
		trace(token.errorMessage);	
	} else {
		tokenStsuu.fromXML(token.token);	
	}
	return tokenStsuu;
}

function buildJwtAccessToken(claims) {
		
	var tokenStsuu = new STSUniversalUser();
	tokenStsuu.addContextAttribute(new com.tivoli.am.fim.trustserver.sts.uuser.Attribute("claim_json","",""+JSON.stringify(claims)));

	// now get a JWT.
	var token = callSts(tokenStsuu.toXML().getDocumentElement(), "urn:jwt:issue");

	if(token.errorMessage != null || token.token == null) {
        trace(tokenResult.errorMessage);
	}

	// Grouse, we got this far, we should have a JWT
	trace("STS Token response: " + token.token.getTextContent());
	return token.token.getTextContent();
}