//==========================================================================
// $Id: UserNamePasswordCredentials.java,v 0.1 Oct 26, 2012 8:08:38 AM cristiand Exp $
// (@) Copyright Sigma Systems (Canada)
// * Based on CVS log
//==========================================================================
package auth.impl.callbackHandlers;

import java.io.IOException;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;

import auth.impl.callbacks.IHeadlessCallback;

/**
 * Callback handler - invokes process method on the callbacks and
 * @version $Revision: $
 * @author $Author: cristiand $
 * @since $Date: Oct 26, 2012 $
 */
public class HeadlessCallbackHandler implements CallbackHandler {

    /* (non-Javadoc)
     * @see javax.security.auth.callback.CallbackHandler#handle(javax.security.auth.callback.Callback[])
     */
    @Override
    public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
        for (int i=0; i<callbacks.length; i++) {
            if (callbacks[i] instanceof IHeadlessCallback) {
                IHeadlessCallback cb = (IHeadlessCallback) callbacks[i];
                cb.process();
            }
        }
    }

}
