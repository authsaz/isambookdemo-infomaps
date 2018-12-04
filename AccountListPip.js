/*
/* 
*/
importPackage(com.tivoli.am.rba.extensions);
importClass(Packages.com.tivoli.am.rba.attributes.AttributeIdentifier);
importPackage(com.ibm.security.access.httpclient);

var url = "http://apps.authsaz.com:7001/api/nf/get_account";

function hasAttribute (requestedAttribute, category) {

    PluginUtils.trace("AccountListPip.hasAttribute(): entry");
    PluginUtils.trace("AccountListPip.hasAttribute(): Looking for " 
        + requestedAttribute + " in " + category);
    // The 'instanceName' global variable should match the issuerId 
    // configured for the attributes.  
    var issuerId = instanceName;

    var pipIssued = false;

    if (issuerId.equals(requestedAttribute.getIssuer()))
    {
         pipIssued = true;
    }       

    PluginUtils.trace("AccountListPip.hasAttribute(): exit: " 
        + requestedAttribute.getURI() + " --> returning " + pipIssued);

    return pipIssued;
}

function getAttributes (context, requestedAttribute, category) {

    PluginUtils.trace("AccountListPip.getAttributes(): entry: " 
        + requestedAttribute + " --> " + category);
    
    /**
     * In case our PIP serves more than 1 attribute, let's still check 
     * for the one we're looking for
     */
    if ("urn:authsaz:attr:accountlist".equals(requestedAttribute.getURI())) { 
        
        var oauthUsernameIdentifier = new AttributeIdentifier(
            "username",
            Attribute.DataType.STRING,
            null);
    
        var oauthUsername = context.getAttribute(Attribute.Category.SUBJECT, 
            oauthUsernameIdentifier);

        
        if (oauthUsername != null && oauthUsername.length > 0) { 
            PluginUtils.trace("AccountListPip.getAttributes(): " + 
            "Found username: " + oauthUsername[0]);
        var username = oauthUsername[0];
            
    PluginUtils.trace("---- username: " + username);
            var headers = new com.ibm.security.access.httpclient.Headers();
            headers.addHeader("Accept", "application/json");
            var httpRequestBodyJSON =  '{"username": "' + username + '"}'; 
            var response =com.ibm.security.access.httpclient.HttpClient.httpPost(url, headers, httpRequestBodyJSON, null, null, null, null, null);
             
            if (response != null){
               var jsonResponseString = response.getBody();
               PluginUtils.trace(jsonResponseString );
               var jsonResponseObj = JSON.parse(jsonResponseString);
                var accountAtrr = new AttributeIdentifier("urn:behsazan:attr:account", Attribute.DataType.STRING,instanceName);

                context.addAttribute(accountAtrr, jsonResponseObj['account']);
            }   
        }
    }        
    else {
        PluginUtils.trace("AccountListPip.getAttributes(): " + 
            "No oauthScopeSubject found!");
    }
}

