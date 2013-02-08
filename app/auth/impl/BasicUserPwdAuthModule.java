package auth.impl;

import java.security.Principal;
import java.util.ArrayList;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.LoginException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import play.mvc.Http;
import play.mvc.Http.Context;
import play.mvc.Http.Request;
import auth.impl.callbackHandlers.UsrPwdCallbackHandler;
import auth.impl.callbacks.HttpUserPwdCallback;
import auth.models.User;

public abstract class BasicUserPwdAuthModule extends AbstractAuthModule {

    private static Logger logger = LoggerFactory.getLogger(BasicUserPwdAuthModule.class);

    /*
     * (non-Javadoc)
     *
     * @see auth.IAuthenticator#getCallbackHandler()
     */
    @Override
    public CallbackHandler getCallbackHandler(Context ctx) {
        return new UsrPwdCallbackHandler();
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
        ArrayList<Callback> callbacks = new ArrayList<Callback>();
        callbacks.add(new HttpUserPwdCallback(req));

        try {
            Callback[] cb = new Callback[callbacks.size()];
            callbackHandler.handle(callbacks.toArray(cb));

            String username = ((HttpUserPwdCallback) cb[0]).username;
            String password = ((HttpUserPwdCallback) cb[0]).password;

            pending = new ArrayList<Principal>();
            User user = validateCredentials(username, password, req);
            if (user != null) {
                pending.add(user);
                return true;
            }
        } catch (Exception e) {
            logger.info("failed user validation.", e);
        }
        return false;
    }

    protected abstract User validateCredentials(String username, String password, Request req) throws LoginException;

}
