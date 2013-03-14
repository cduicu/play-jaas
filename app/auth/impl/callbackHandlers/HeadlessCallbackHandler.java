package auth.impl.callbackHandlers;

import java.io.IOException;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;

import play.mvc.Http;
import play.mvc.Http.Context;
import auth.impl.callbacks.HeadlessCallback;

public class HeadlessCallbackHandler implements CallbackHandler {

    private Context ctx;

    public HeadlessCallbackHandler(Http.Context ctx) {
        this.ctx = ctx;
    }

    /* (non-Javadoc)
     * @see javax.security.auth.callback.CallbackHandler#handle(javax.security.auth.callback.Callback[])
     */
    @Override
    public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
        for (int i=0; i<callbacks.length; i++) {
            if (callbacks[i] instanceof HeadlessCallback) {
                HeadlessCallback cb = (HeadlessCallback) callbacks[i];
                cb.process(ctx);
            }
        }
    }

}
