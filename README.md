play-jaas
=========

This is an authentication module for Play 2.x framework which performs the authentication via JAAS.
Note that this will protect the controllers and not the resources in the /public directory. 

Dependencies and 3rd Party Libraries
------------------------------------
The project contains a number of authentication modules. 
Depending on which module you want you may depend on additional 3rd party libraries. The following is a 
list of libraries needed to compile the code.

- Play 2.0.3
- OpenSAML Stack (in /lib directory):
    - opensaml-2.5.3.jar
    - openws-1.4.4.jar
    - xmltooling-1.3.4.jar
    - commons-httpclient-3.1
 
 Note that when using the federated authentication module (SAML2) there are additional libraries required at runtime.
 
 Usage
 -----
 - Annotate the controllers you want to protect with:
 @Security.Authenticated(Secured.class)
 
 - Configure the authentication - jaas configuration. 
 A JAAS configuration file must be provided to the JVM. Read the javadoc from auth.Configuration for more details.
 
 - Configure the authentication - runtime configuration
 Select the authentication module you want to use. Depending on the module used you might need to do more configuration. 
 For instance if you use OpenAM you need to setup OpenAM.
 
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
 
 
 