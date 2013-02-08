package auth;

import auth.impl.FederatedAuthModule;
import auth.impl.FileAuthModule;
import auth.impl.JDBCAuthModule;
import auth.impl.OpenAMAuthModule;
import auth.impl.PassThruAuthModule;
import auth.impl.StubAuthModule;

/**
 * Default configuration provided. Make sure you change it as per your needs. The configuration here
 * must also match the JAAS configuration file. The JAAS configuration file must be loaded into the
 * JVM like this: <code>-Djava.security.auth.login.config=C:/jaas.config</code>
 *
 * <p>
 * Example JAAS configuration file for built-in modules:
 *
 * <pre>
 * PassThruAuth {
 *     auth.impl.PassThruAuthModule required debug=true;
 * };
 * StubAuth {
 *     auth.impl.StubAuthModule required debug=true;
 * };
 * FileAuth {
 *     auth.impl.FileAuthModule required debug=true pwdFile="c:/passwd";
 * };
 * JDBCAuth {
 *     auth.impl.JDBCAuthModule required dbDriver="com.mysql.jdbc.Driver" dbURL="jdbc:mysql://localhost:3306/login";
 * };
 * OpenAMAuth {
 *     auth.impl.OpenAMAuthModule required debug=true userAttr="username" openAmUrl="http://openam.mybox.com:8080/openam";
 * };
 * FederatedAuth {
 *     auth.impl.FederatedAuthModule required debug=true
 *     userAttr="username"
 *     idpUrl="http://openam.mybox.com:8080/openam/SSOPOST/metaAlias/idp"
 *     samlIssuerUrl="http://play.mybox.com:9000"
 *     assertionConsumerServiceUrl="http://play.mybox.com:9000/sp/consumer";
 * };
 * </pre>
 */
public class Configuration {

    public static final String   RESPONSE_TYPE_JSON     = "json";
    public static final String   RESPONSE_TYPE_REDIRECT = "redirect";

    // constants for built-in auth modules
    public static final String   HANDLER_NO_AUTH        = "noAuthHandler";
    public static final String   HANDLER_USER_PWD_STUB  = StubAuthModule.class.getName();
    public static final String   HANDLER_USER_PWD_FILE  = FileAuthModule.class.getName();
    public static final String   HANDLER_USER_PWD_JDBC  = JDBCAuthModule.class.getName();
    public static final String   HANDLER_PASS_THRU      = PassThruAuthModule.class.getName();
    public static final String   HANDLER_OPENAM         = OpenAMAuthModule.class.getName();
    public static final String   HANDLER_SAML2          = FederatedAuthModule.class.getName();

    // when unauthorized it will try to login
    public static final String   AUTH_METHOD_ACTIVE     = "active";
    // when unauthorized it will simply show a notSignedIn page
    public static final String   AUTH_METHOD_PASSIVE    = "passive";

    // some default values
    private static Configuration instance;
    public String                authnHandler           = HANDLER_OPENAM;
    public String                authFailedResponseType = RESPONSE_TYPE_JSON;
    public String                urlLogout              = "/";
    public String                urlAuthSucceeded       = "/";
    public String                urlAuthFailed          = "/";
    public boolean               followOriginalUri      = true;
    public String                authnMethod            = AUTH_METHOD_ACTIVE;
    public boolean               ssoLogout              = false; // if true, the logout will invoke logout on Idp

    private Configuration() {
    }

    public static Configuration getInstance() {
        if (instance == null) {
            synchronized (Configuration.class) {
                if (instance == null) {
                    instance = new Configuration();
                }
            }
        }
        return instance;
    }

}
