/*
    code from https://philipnye.com/2015/05/15/isam-context-based-access-pip-for-oauth/
*/
importPackage(com.tivoli.am.rba.extensions);
importClass(Packages.com.tivoli.am.rba.attributes.AttributeIdentifier);

function hasAttribute (requestedAttribute, category) {

    PluginUtils.trace("oauthscope_pip_rile.hasAttribute(): entry");
    PluginUtils.trace("oauthscope_pip_rile.hasAttribute(): Looking for " 
        + requestedAttribute + " in " + category);
    // The 'instanceName' global variable should match the issuerId 
    // configured for the attributes.  
    var issuerId = instanceName;

    var pipIssued = false;

    if (issuerId.equals(requestedAttribute.getIssuer()))
    {
         pipIssued = true;
    }       

    PluginUtils.trace("oauthscope_pip_rile.hasAttribute(): exit: " 
        + requestedAttribute.getURI() + " --> returning " + pipIssued);

    return pipIssued;
}

function getAttributes (context, requestedAttribute, category) {

    PluginUtils.trace("oauthscope_pip_rile.getAttributes(): entry: " 
        + requestedAttribute + " --> " + category);
    
    /**
     * In case our PIP serves more than 1 attribute, let's still check 
     * for the one we're looking for
     */
    if ("urn:ibm:security:iam:oauth:scope".equals(requestedAttribute.getURI())) { 
        
        /**
         * Get the oauthScopeSubject attribute.  Note if we are using the 
         * EAS instead of oauth-auth in WebSEAL, we would instead get the 
         * oauthScopeResource attribute and lookin the RESOURCE attribute 
         * not the SUBJECT.
         */
        var oauthScopeSubjectIdentifier = new AttributeIdentifier(
            "urn:ibm:security:subject:oauthScope",
            Attribute.DataType.STRING,
            null);
    
        var oauthScopeSubject = context.getAttribute(Attribute.Category.SUBJECT, 
            oauthScopeSubjectIdentifier);   
    
        if (oauthScopeSubject != null && oauthScopeSubject.length > 0) { 
            PluginUtils.trace("oauthscope_pip_rile.getAttributes(): " 
              + "Found scopes: " + oauthScopeSubject[0]);
            
        /**
         * Try a cast so we don't try and do it on an Object data type 
         * otherwise you get a Java Object exception.
         */
        var    stringScopeCast = String(oauthScopeSubject[0]);
        
        //Turn our static string into a multi valued attribute.  Make an 
        // assumption of no whitespace. 
        var oauthScopes = stringScopeCast.split(",")
        
        /**
         * Create the new attribute identifier to populate it back 
         * into the context.
         *
         * Instance name is the name of the PIP, so we can use this *but* if 
         * we have a PIP that is the issuer for multiple issuer IDs, 
         * we couldn't use it as the hasAttribute would have checked against 
         * 1 or more and then manually returned true.         
         */
        var oauthScopeAttribute = new AttributeIdentifier(
            "urn:ibm:security:iam:oauth:scope",
            Attribute.DataType.STRING,
            instanceName);
    
        context.addAttribute(oauthScopeAttribute, oauthScopes);
        
        PluginUtils.trace("oauthscope_pip_rile.getAttributes(): " 
            + "adding urn:ibm:security:iam:oauth:scope " + oauthScopes);
            
        }        
        else {
            PluginUtils.trace("oauthscope_pip_rile.getAttributes(): " + 
                "No oauthScopeSubject found!");
        }        
    }

    if ("urn:ibm:security:iam:oauth:client:id"
              .equals(requestedAttribute.getURI())) {    
                
        /**
         * Retrieve the oauth_token_client_id from the XACML passed from 
         * WebSEAL to RTSS. You can find a list of additional attributes you 
         * could use by looking in the pdweb.rtss.
         * For example - 
         * access_token
         * client_type
         * scope (though already an attribute which is populated from 
         * urn:ibm:security:subject:oauthScope which is also sent)
         * urn:oasis:names:tc:xacml:1.0:action:action-id (though already in 
         * the attribute list as the 'action' which is the HTTP Method)
         */
        var oauthClientIdIdentifier = new AttributeIdentifier(
            "oauth_token_client_id",
            Attribute.DataType.STRING,
            null);
    
        var oauthClientId = context.getAttribute(Attribute.Category.SUBJECT, 
            oauthClientIdIdentifier);   
        
        if (oauthClientId != null && oauthClientId.length > 0) { 
            PluginUtils.trace("oauthscope_pip_rile.getAttributes(): " + 
            "Found oauth_token_client_id: " + oauthClientId[0]);
            
            var oauthClientIdAttribute = new AttributeIdentifier(
                "urn:ibm:security:iam:oauth:client:id",
                Attribute.DataType.STRING,
                instanceName);
        
            context.addAttribute(oauthClientIdAttribute, [oauthClientId[0]]);
            
            PluginUtils.trace("oauthscope_pip_rile.getAttributes(): " + 
                "adding urn:ibm:security:iam:oauth:client:id " 
                     + [oauthClientId[0]]);        
        
        }
        else {
            PluginUtils.trace("oauthscope_pip_rile.getAttributes(): " 
                + "No oauth_token_client_id found!");
        }        
    }    
    
	
	if ("urn:ibm:security:iam:oauth:username"
              .equals(requestedAttribute.getURI())) {    
                
        /**
         * Retrieve the username from the XACML passed from 
         * WebSEAL to RTSS. You can find a list of additional attributes you 
         * could use by looking in the pdweb.rtss.
         * For example - 
		 * username
         * access_token
         * client_type
         * scope (though already an attribute which is populated from 
         * urn:ibm:security:subject:oauthScope which is also sent)
         * urn:oasis:names:tc:xacml:1.0:action:action-id (though already in 
         * the attribute list as the 'action' which is the HTTP Method)
         */
        var oauthUsernameIdentifier = new AttributeIdentifier(
            "username",
            Attribute.DataType.STRING,
            null);
    
        var oauthUsername = context.getAttribute(Attribute.Category.SUBJECT, 
            oauthUsernameIdentifier);   
        
        if (oauthUsername != null && oauthUsername.length > 0) { 
            PluginUtils.trace("oauthscope_pip_rile.getAttributes(): " + 
            "Found username: " + oauthUsername[0]);
            
            var oauthUsernameAttribute = new AttributeIdentifier(
                "urn:ibm:security:iam:oauth:username",
                Attribute.DataType.STRING,
                instanceName);
        
            context.addAttribute(oauthUsernameAttribute, [oauthUsername[0]]);
            
            PluginUtils.trace("oauthscope_pip_rile.getAttributes(): " + 
                "adding urn:ibm:security:iam:oauth:username " 
                     + [oauthUsername[0]]);        
        
        }
        else {
            PluginUtils.trace("oauthscope_pip_rile.getAttributes(): " 
                + "No username found!");
        }        
    }
    PluginUtils.trace("oauthscope_pip_rile.getAttributes(): exit");
}