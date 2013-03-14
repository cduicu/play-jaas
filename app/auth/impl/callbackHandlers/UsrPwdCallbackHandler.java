package auth.impl.callbackHandlers;

import java.io.IOException;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import play.mvc.Http;
import play.mvc.Http.Context;

import auth.impl.callbacks.HttpUserPwdCallback;

public class UsrPwdCallbackHandler implements CallbackHandler {

    private Context ctx;

    public UsrPwdCallbackHandler(Http.Context ctx) {
        this.ctx = ctx;
    }

    /* (non-Javadoc)
     * @see javax.security.auth.callback.CallbackHandler#handle(javax.security.auth.callback.Callback[])
     */
    @Override
    public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
        for (int i=0; i<callbacks.length; i++) {
            if (callbacks[i] instanceof HttpUserPwdCallback) {
                HttpUserPwdCallback cb = (HttpUserPwdCallback) callbacks[i];
                cb.process(ctx);
            }
        }
    }

}
