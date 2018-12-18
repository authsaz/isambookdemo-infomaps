importClass(Packages.java.util.UUID);
importClass(Packages.com.tivoli.am.fim.trustserver.sts.utilities.IDMappingExtUtils);

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
    IDMappingExtUtils.getIDMappingExtCache().put(uuid,JSON.stringify(data),expiresInSeconds);
    return uuid;
}

function verify_response(variables){
    var uuid = context.get(Scope.SESSION,"urn:authsaz:ref","uuid");
    if(uuid == variables.param_response){
        var json = JSON.parse(IDMappingExtUtils.getIDMappingExtCache().get(uuid));
        if(json.isAuth){
            context.set(Scope.SESSION,"urn:authsaz:ref","uuid",""); // invalidate uuid
            return true;
        }
    }
    return false;
}

function load_data_from_challenge(challenge){
    return JSON.parse(IDMappingExtUtils.getIDMappingExtCache().get(challenge));
}

function solve_challenge_get_response(token){
    var json = JSON.parse(IDMappingExtUtils.getIDMappingExtCache().get(token));
    json["isAuth"] = true;
    IDMappingExtUtils.getIDMappingExtCache().put(token,JSON.stringify(json),expiresInSeconds);
    return token;
}
    