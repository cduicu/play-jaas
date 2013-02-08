package auth.impl;

import java.security.Principal;
import java.util.ArrayList;
import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.LoginException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import play.mvc.Http;
import play.mvc.Http.Context;
import auth.impl.callbackHandlers.HeadlessCallbackHandler;
import auth.impl.callbacks.HttpCookieCallback;
import auth.impl.callbacks.HttpRequestHeaderCallback;
import auth.impl.callbacks.OpenAMAttributesCallback;
import auth.models.User;
import auth.models.UserToken;

public class OpenAMAuthModule extends AbstractAuthModule {

    private static Logger logger = LoggerFactory.getLogger(OpenAMAuthModule.class);
    private static final String OPEN_AM_AUTH_MODULE = "OpenAMAuth";
    private static final String OPEN_AM_PREFIX      = "HTTP_";
    private static final String USER_ID             = "username";
    private static final String USER_FULLNAME       = "fullname";
    private static final String USER_EMAIL          = "email";
    private static final String USER_PHONE          = "phone";
    private String userAttr;
    private String fullNameAttr;
    private String emailAttr;
    private String phoneAttr;
    private String openAmUrl;

    /* (non-Javadoc)
     * @see auth.IAuthModule#getCallbackHandler(play.mvc.Http.Context)
     */
    @Override
    public CallbackHandler getCallbackHandler(Context ctx) {
        return new HeadlessCallbackHandler();
    }

    /* (non-Javadoc)
     * @see auth.IAuthModule#getModuleName()
     */
    @Override
    public String getModuleName() {
        return OPEN_AM_AUTH_MODULE;
    }

    /* (non-Javadoc)
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
        callbacks.add(new HttpCookieCallback(req, userAttr));
        callbacks.add(new HttpCookieCallback(req, fullNameAttr));
        callbacks.add(new HttpCookieCallback(req, phoneAttr));
        callbacks.add(new HttpCookieCallback(req, emailAttr));

        callbacks.add(new HttpRequestHeaderCallback(req, userAttr));
        callbacks.add(new HttpRequestHeaderCallback(req, fullNameAttr));
        callbacks.add(new HttpRequestHeaderCallback(req, phoneAttr));
        callbacks.add(new HttpRequestHeaderCallback(req, emailAttr));

        try {
            Callback[] cb = new Callback[callbacks.size()];
            callbackHandler.handle(callbacks.toArray(cb));

            String userid = null, fullname = null, email = null, phone = null;
            for (int i=0; i<cb.length; i++) {
                if (cb[i] instanceof HttpRequestHeaderCallback) {
                    HttpRequestHeaderCallback c = (HttpRequestHeaderCallback) cb[i];
                    if (c.getName().equals(userAttr) && c.getValue() != null) userid = c.getValue();
                    if (c.getName().equals(fullNameAttr) && c.getValue() != null) fullname = c.getValue();
                    if (c.getName().equals(emailAttr) && c.getValue() != null) email = c.getValue();
                    if (c.getName().equals(phoneAttr) && c.getValue() != null) phone = c.getValue();
                } else if (cb[i] instanceof HttpCookieCallback) {
                    HttpCookieCallback c = (HttpCookieCallback) cb[i];
                    if (c.getName().equals(userAttr) && c.getValue() != null) userid = c.getValue();
                    if (c.getName().equals(fullNameAttr) && c.getValue() != null) fullname = c.getValue();
                    if (c.getName().equals(emailAttr) && c.getValue() != null) email = c.getValue();
                    if (c.getName().equals(phoneAttr) && c.getValue() != null) phone = c.getValue();
                } else if (cb[i] instanceof OpenAMAttributesCallback) {
                    // do nothing
                } else {
                    logger.info("Don't know how to work with callback: " + cb[i].getClass().getName());
                }
            }

            if (userid == null) {
                // if not found in HTTP request header or cookies, fall back to back channel call to OpenAM
                logger.debug("nothing found in headers, try REST API ...");
                ArrayList<String> lst = new ArrayList<String>();
                lst.add("uid"); lst.add("cn"); lst.add("telephonenumber"); lst.add("mail");
                OpenAMAttributesCallback amcb = new OpenAMAttributesCallback(req, openAmUrl, lst);
                amcb.process();
                userid = amcb.getValue("uid");
                if (fullname == null) fullname = amcb.getValue("cn");
                if (phone == null) phone = amcb.getValue("telephonenumber");
                if (email == null) email = amcb.getValue("mail");
            }

            pending = new ArrayList<Principal>();
            if (userid != null) {
                User user = UserToken.createUserToken(userid, "cangetin", req);
                user.fullName = fullname;
                //user.email = email; user.phone = phone;
                pending.add(user);
                return true;
            }
        } catch (Exception e) {
            logger.info("failed user validation.", e);
        }
        return false;
    }

    @Override
    public void initialize(Subject subject, CallbackHandler callbackHandler, Map<String, ?> sharedState,
            Map<String, ?> options) {
        super.initialize(subject, callbackHandler, sharedState, options);
        userAttr = getOption("userAttr", null);
        if (userAttr == null) {
            userAttr = USER_ID;
            logger.debug("userAttr not configured; using default: " + userAttr);
        }
        userAttr = OPEN_AM_PREFIX + userAttr;

        fullNameAttr = getOption("fullNameAttr", null);
        if (fullNameAttr == null) {
            fullNameAttr = USER_FULLNAME;
            logger.debug("fullNameAttr not configured; using default: " + fullNameAttr);
        }
        fullNameAttr = OPEN_AM_PREFIX + fullNameAttr;

        emailAttr = getOption("emailAttr", null);
        if (emailAttr == null) {
            emailAttr = USER_EMAIL;
            logger.debug("emailAttr not configured; using default: " + emailAttr);
        }
        emailAttr = OPEN_AM_PREFIX + emailAttr;

        phoneAttr = getOption("phoneAttr", null);
        if (phoneAttr == null) {
            phoneAttr = USER_PHONE;
            logger.debug("phoneAttr not configured; using default: " + phoneAttr);
        }
        phoneAttr = OPEN_AM_PREFIX + phoneAttr;

        openAmUrl = getOption("openAmUrl", null);
        if (openAmUrl == null) {
            logger.debug("openAmUrl not configured");
        }
    }
}
