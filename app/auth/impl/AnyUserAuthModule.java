package auth.impl;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import play.mvc.Http.Request;
import auth.models.User;
import auth.models.UserToken;

/**
 * A concrete authentication module. This is a simple stub to be used for testing.
 * It hard-codes a number of users in a static.
 */
public class AnyUserAuthModule extends BasicUserPwdAuthModule {

    private static Logger       logger      = LoggerFactory.getLogger(AnyUserAuthModule.class);
    private static final String AUTH_MODULE = "AnyUserAuth";

    /*
     * (non-Javadoc)
     *
     * @see auth.IAuthenticator#getModuleName()
     */
    @Override
    public String getModuleName() {
        return AUTH_MODULE;
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
        password = password == null ? "cangetin" : password;
        User user = UserToken.createUserToken(username, password, req);
        user.fullName = username;
        return user;
    }

}
