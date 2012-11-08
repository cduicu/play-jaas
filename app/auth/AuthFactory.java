//==========================================================================
// $Id: AuthFactory.java,v 1.1.2.1 2012/07/10 19:06:57 cristiand Exp $
// (@) Copyright Sigma Systems (Canada)
// * Based on CVS log
//==========================================================================
package auth;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @version $Revision: 1.1.2.1 $
 * @author $Author: cristiand $
 * @since $Date: 2012/07/10 19:06:57 $
 */
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
