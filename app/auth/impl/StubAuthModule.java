package auth.impl;

import java.util.HashMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import play.mvc.Http.Request;
import auth.models.User;
import auth.models.UserToken;

/**
 * A concrete authentication module. This is a simple stub to be used for testing.
 * It hard-codes a number of users in a static.
 */
public class StubAuthModule extends BasicUserPwdAuthModule {

    private static Logger                  logger           = LoggerFactory.getLogger(StubAuthModule.class);
    private static final String            AUTH_MODULE_STUB = "StubAuth";
    private static HashMap<String, String> users            = new HashMap<String, String>();
    static {
        users.put("test", "John Doe");
        users.put("aalli", "Ally Alligator");
        users.put("bbear", "Billy Bear");
        users.put("ccat", "Carrie Cat");
        users.put("dduck", "David Duck");
        users.put("eeagle", "Eva Eagle");
    }

    /*
     * (non-Javadoc)
     *
     * @see auth.IAuthenticator#getModuleName()
     */
    @Override
    public String getModuleName() {
        return AUTH_MODULE_STUB;
    }

    /**
     * @param username
     * @param password
     * @param req
     * @return
     */
    @Override
    protected User validateCredentials(String username, String password, Request req) {
        logger.debug("validateCredentials()");
        String u = users.get(username);
        if (u != null && password.equals("pw" + username)) {
            User user = UserToken.createUserToken(username, password, req);
            user.fullName = users.get(username);
            return user;
        }
        return null;
    }

}
