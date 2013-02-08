package auth;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class AuthFactory {

    private static Logger logger = LoggerFactory.getLogger(AuthFactory.class);

    public static IAuthModule getAuthenticator(String authnHandler) {
        IAuthModule auth = null;
        try { // load authentication handler
            auth = (IAuthModule) AuthFactory.class.getClassLoader().loadClass(authnHandler).newInstance();
            logger.debug("Loaded authentication module: " + authnHandler);
        } catch (Exception ex) {
            logger.error("Cannot load authenticator: " + authnHandler, ex);
        }
        return auth;
    }

}
