play-jaas
=========

This is an authentication module for Play 2.2.2 framework which performs the authentication via JAAS.
Note that this will protect the controllers and not the resources in the /public directory. 

Dependencies and 3rd Party Libraries
------------------------------------
The project contains a number of authentication modules. 
Depending on which module you want you may depend on additional 3rd party libraries. The following is a 
list of libraries needed to compile the code.

- Play 2.2.2
- OpenSAML Stack (in /lib directory):
    - opensaml-2.5.3.jar
    - openws-1.4.4.jar
    - xmltooling-1.3.4.jar
 
 Note that when using the federated authentication module (SAML2) there are additional libraries required at runtime.
 
 Usage
 -----
 - add the play-jaas library as dependency to your project. (ie. copy the jar to lib/ folder of your Play project)
 
 - Annotate the controllers you want to protect with:
 @Security.Authenticated(Secured.class)
 
 - Configure the authentication - jaas configuration. 
 A JAAS configuration file must be provided to the JVM.  You can do that via the standard system property defined by JAAS (-Djava.security.auth.login.config=[absolutePath]/[YourJAASConfigFile])
Example JAAS configuration file content for built-in modules:

``` 
  PassThruAuth {
      auth.impl.PassThruAuthModule required debug=true;
  };
  StubAuth {
      auth.impl.StubAuthModule required debug=true;
  };
  FileAuth {
      auth.impl.FileAuthModule required debug=true pwdFile="c:/passwd";
  };
  JDBCAuth {
      auth.impl.JDBCAuthModule required dbDriver="com.mysql.jdbc.Driver" dbURL="jdbc:mysql://localhost:3306/login";
  };
  OpenAMAuth {
      auth.impl.OpenAMAuthModule required debug=true userAttr="username" openAmUrl="http://openam.mybox.com:8080/openam";
  };
  FederatedAuth {
      auth.impl.FederatedAuthModule required debug=true
      userAttr="username"
      idpUrl="http://openam.mybox.com:8080/openam/SSOPOST/metaAlias/idp"
      samlIssuerUrl="http://play.mybox.com:9000"
      assertionConsumerServiceUrl="http://play.mybox.com:9000/sp/consumer";
  };
 ```
 
 - Configure the authentication - runtime configuration
 Select the authentication module you want to use. Depending on the module used you might need to do more configuration. 
 For instance if you use OpenAM you need to setup OpenAM.
 Configuration is done by changing the defaults in the auth.Configuration class.
 
 Authentication Modules
 -----------------------
 - No authentication - bypass the entire code and allow user to access protected content
 - Pass-thru authentication - allow all
 - Stub User name & password - allow a predefined list of users.
 - File based - users and passwords are stored in a file (password is hashed)
 - JDBC based - users and passwords are stored in a database
 - OpenAM - using OpenAM Identity manager and a policy agent installed in a Apache proxy
 - Federated - uses SAML. You can use OpenAM in this case as well.
  
 License
 -------
 This library is released under the Apache Software License, version 2.
 
 
 