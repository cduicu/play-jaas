//==========================================================================
// $Id: AuthStub.java,v 1.1.2.2 2012/09/07 16:31:36 cristiand Exp $
// (@) Copyright Sigma Systems (Canada)
// * Based on CVS log
//==========================================================================
package auth.impl;

import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.LoginException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import play.mvc.Http;
import play.mvc.Http.Context;
import auth.impl.callbackHandlers.HeadlessCallbackHandler;
import auth.models.User;
import auth.models.UserToken;

/**
 * A concrete authentication module. This is a simple stub to be used for testing.
 *
 * @version $Revision: 1.1.2.2 $
 * @author $Author: cristiand $
 * @since $Date: 2012/09/07 16:31:36 $
 */
public class PassThruAuthModule extends AbstractAuthModule {

    private static Logger logger = LoggerFactory.getLogger(PassThruAuthModule.class);
    private static final String PASS_THRU_AUTH_MODULE = "PassThruAuth";

    /*
     * (non-Javadoc)
     *
     * @see auth.IAuthenticator#getModuleName()
     */
    @Override
    public String getModuleName() {
        return PASS_THRU_AUTH_MODULE;
    }

    /* (non-Javadoc)
     * @see auth.IAuthModule#getCallbackHandler(play.mvc.Http.Context)
     */
    @Override
    public CallbackHandler getCallbackHandler(Context ctx) {
        return new HeadlessCallbackHandler();
    }

    /*
     * (non-Javadoc)
     *
     * @see javax.security.auth.spi.LoginModule#login()
     */
    @Override
    public boolean login() throws LoginException {
        logger.debug("login()");
        if (callbackHandler == null) {
            throw new LoginException("Error: no CallbackHandler available!");
        }
        Http.Request req = Context.current.get().request(); // I'm counting on having been set
                                                            // before calling login
        try {
            User user = UserToken.createUserToken("demo", "cangetin", req);
            user.fullName = "John Doe";
            pending.add(user);
            return true;
        } catch (Exception e) {
            logger.info("failed user validation.", e);
        }
        return false;
    }

}
