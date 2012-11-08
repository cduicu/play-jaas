//==========================================================================
// $Id: SAML2CallbackHandler.java,v 0.1 Nov 5, 2012 1:52:12 PM cristiand Exp $
// (@) Copyright Sigma Systems (Canada)
// * Based on CVS log
//==========================================================================
package auth.impl.callbackHandlers;

import java.io.IOException;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;

import auth.impl.callbacks.AuthnResponseCallback;

/**
 * @version $Revision: $
 * @author $Author: cristiand $
 * @since $Date: Nov 5, 2012 $
 */
public class SAML2CallbackHandler implements CallbackHandler {


    /* (non-Javadoc)
     * @see javax.security.auth.callback.CallbackHandler#handle(javax.security.auth.callback.Callback[])
     */
    @Override
    public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
        for (int i=0; i<callbacks.length; i++) {
            if (callbacks[i] instanceof AuthnResponseCallback) {
                AuthnResponseCallback cb = (AuthnResponseCallback) callbacks[i];
                cb.process();
            }
        }
    }
}
