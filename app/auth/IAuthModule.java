//==========================================================================
// $Id: IAuthenticator.java,v 1.1.2.1 2012/07/10 19:06:57 cristiand Exp $
// (@) Copyright Sigma Systems (Canada)
// * Based on CVS log
//==========================================================================
package auth;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.spi.LoginModule;

import play.mvc.Http.Context;
import play.mvc.Result;

/**
 * The Authentication Module interface.
 *
 * @version $Revision: 1.1.2.1 $
 * @author $Author: cristiand $
 * @since $Date: 2012/07/10 19:06:57 $
 */
public interface IAuthModule extends LoginModule {

    /**
     * The authentication module will act as a factory for the callback handler, meaning that this
     * method is provided in order to put the creation of the callback handler in the same place as
     * the code that uses it (ie. login())
     *
     * @param ctx - the HTTP context
     * @return
     */
    CallbackHandler getCallbackHandler(Context ctx);

    /**
     * Each authentication module must have a unique name. This name must match the name used in the
     * JAAS configuration file.
     *
     * @return the module name
     */
    String getModuleName();

    /**
     * Invoked if the authentication fails.
     *
     * @param e - the reason for failure
     * @return the page that the user is redirected to
     */
    Result onAuthFailed(Exception e);

    /**
     * Invoked if the authentication succeeds.
     *
     * @param subject - the subject created for the user
     * @return the page that the user is redirected to
     */
    Result onAuthSucceeded(Subject subject);

}
