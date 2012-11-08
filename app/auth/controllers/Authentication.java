//==========================================================================
// $Id: Authentication.java,v 1.1.2.3 2012/07/10 19:06:58 cristiand Exp $
// (@) Copyright Sigma Systems (Canada)
// * Based on CVS log
//==========================================================================
package auth.controllers;

import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import play.mvc.Controller;
import play.mvc.Http.Context;
import play.mvc.Result;
import auth.AuthFactory;
import auth.Configuration;
import auth.IAuthModule;
import auth.WebSession;

/**
 * Handles user authentication.
 * It requires configuration of the authentication module via util.Config.getAuthnHandler();
 *
 * @version $Revision: 1.1.2.3 $
 * @author $Author: cristiand $
 * @since $Date: 2012/07/10 19:06:58 $
 */
public class Authentication extends Controller {

    private static Logger logger = LoggerFactory.getLogger(Authentication.class);

    /**
     * Login using JAAS.
     * Invoked by security authentication so the context must be passed as argument.
     *
     * @param ctx - HTTP context
     * @return
     */
    public static Result login(Context ctx) {
        IAuthModule auth = AuthFactory.getAuthenticator(Configuration.getInstance().authnHandler);
        if (auth == null) {
            return badRequest("Failed loading Authentication module!");
        }
        try {
            CallbackHandler cbh = auth.getCallbackHandler(ctx);
            LoginContext lc = null;
            if (cbh == null) {
                // must set a default callback handler in configuration
                lc = new LoginContext(auth.getModuleName());
            } else {
                lc = new LoginContext(auth.getModuleName(), cbh);
            }
            Context.current.set(ctx);
            //auth.setContext(ctx); // auth module gets initialized ... set context now
            lc.login();
            return auth.onAuthSucceeded(lc.getSubject());
        } catch (LoginException e) {
            return auth.onAuthFailed(e);
        } catch (SecurityException e) {
            return auth.onAuthFailed(e);
        }
    }

    public static Result logout() {
        WebSession.removeSession(session("uuid"));
        session().clear();
        if (Configuration.getInstance().ssoLogout) {
            IAuthModule auth = AuthFactory.getAuthenticator(Configuration.getInstance().authnHandler);
            if (auth != null) {
                if (auth.equals(Configuration.HANDLER_SAML2)) {
                    // TODO: get configuration and invoke logout
                } else if (auth.equals(Configuration.HANDLER_OPENAM)) {
                    // TODO: get configuration and invoke logout
                }
            }
        }
        //Authenticate.logout() // TODO
        return Controller.redirect(Configuration.getInstance().urlLogout);
    }

    /**
     * Used for Federated Authentication (SAML2). Process the AuthnResponse from IdP.
     *
     * @return
     */
    public static Result samlAuthnResponse() {
        logger.debug("samlAuthnResponse()");
        return login(ctx());
    }

}