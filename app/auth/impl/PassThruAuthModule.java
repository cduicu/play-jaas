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
import auth.impl.callbackHandlers.HeadlessCallbackHandler;
import auth.impl.callbacks.PassThruCallback;
import auth.models.User;
import auth.models.UserToken;

/**
 * A concrete authentication module. This is a simple stub to be used for testing.
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
        return new HeadlessCallbackHandler(ctx);
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

        ArrayList<Callback> callbacks = new ArrayList<Callback>();
        callbacks.add(new PassThruCallback());

        try {
            Callback[] cb = new Callback[callbacks.size()];
            callbackHandler.handle(callbacks.toArray(cb));

            Http.Request req = ((PassThruCallback) cb[0]).getOriginalRequest();

            pending = new ArrayList<Principal>();
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
