var secret = "CHANGE_ME";
var expiresInSeconds = 60;

/*
implementation: 

1       cache
2       WebService
3       JWT
4       STS
*/

var implementation = 1;

switch(implementation){
   case 1: // cache
       importMappingRule("api_policy_cache");
       conf = {};
       break;
   case 2: // WebService
       importMappingRule("api_policy_WebService");
       conf = {
           webservice: "http://apps.authsaz.com:7001/internal/token"
       };
       break;
   case 3: // JWT
       importMappingRule("api_policy_JWT");
       conf = {secret: secret };
       break;
   case 4: // STS
       importMappingRule("api_policy_STS");
       conf = {};
       break;
   default:
       throw "no implementation is selected.";
}
