package auth.impl;

import auth.Configuration;
import auth.IAuthModule;
import auth.WebSession;
import auth.models.User;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import play.i18n.Messages;
import play.libs.Json;
import play.mvc.Controller;
import play.mvc.Result;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.LoginException;
import java.security.Principal;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

public abstract class AbstractAuthModule implements IAuthModule {

    private static Logger     logger          = LoggerFactory.getLogger(AbstractAuthModule.class);
    protected Map<String, ?>  attrs;
    protected User            user;

    protected List<Principal> pending = new ArrayList<Principal>();
    protected List<Principal> principals = new ArrayList<Principal>();
    protected boolean         commitSucceeded = false;

    protected Subject         subject;
    protected CallbackHandler callbackHandler;
    protected Map<String, String>  sharedState;
    protected Map<String, ?>  options;

    /*
     * (non-Javadoc)
     *
     * @see javax.security.auth.spi.LoginModule#initialize(javax.security.auth.Subject,
     * javax.security.auth.callback.CallbackHandler, java.util.Map, java.util.Map)
     */
    @Override
    public void initialize(Subject subject, CallbackHandler callbackHandler, Map<String, ?> sharedState,
            Map<String, ?> options) {
        this.subject = subject;
        this.callbackHandler = callbackHandler;
        this.sharedState = (Map<String, String>) sharedState;
        this.options = options;
        logger.trace("initialized: cb=" + callbackHandler + "; subject=" + subject
                + "; sharedState=" + sharedState + "; opts=" + options);
    }

    /*
     * (non-Javadoc)
     *
     * @see controllers.auth.IAuthenticator#onAuthFailed(java.lang.String)
     */
    @Override
    public Result onAuthFailed(Exception e) {
        logger.info("Failed authenticating user! Reason: " + (e != null ? e.getMessage() : "unknown"), e);
        String respType = Configuration.getInstance().authFailedResponseType;
        if (respType == Configuration.RESPONSE_TYPE_JSON) {
            ObjectNode result = Json.newObject();
            result.put("authResult", "fail");
            result.put("errors", Messages.get("invalid_credentials"));
            // or you can try: ok(string).as("application/json")
            return Controller.ok(result);
        } else if (respType == Configuration.RESPONSE_TYPE_REDIRECT) {
            return Controller.redirect(Configuration.getInstance().urlAuthFailed);
        }
        return Controller.forbidden();
    }

    /*
     * (non-Javadoc)
     *
     * @see controllers.auth.IAuthenticator#onAuthSucceeded(models.User)
     */
    @Override
    public Result onAuthSucceeded(Subject subject) {
        User user = getUser(subject);
        logger.info("User '" + user.name + "' successfully signed in!");
        WebSession session = WebSession.newSession(Controller.ctx().session());
        session.put("user", subject);
        if (Configuration.getInstance().followOriginalUri) {
            return Controller.redirect(Controller.ctx().request().uri());
        } else {
            return Controller.redirect(Configuration.getInstance().urlAuthSucceeded);
        }
    }

    /**
     *
     * @param s
     * @param p
     */
    private void putPrincipal(Set<Principal> s, Principal p) {
        logger.trace("added principal: " + p);
        s.add(p);
        principals.add(p);
    }

    /**
     * <p>
     * This method is called if the LoginContext's overall authentication succeeded (the relevant
     * REQUIRED, REQUISITE, SUFFICIENT and OPTIONAL LoginModules succeeded).
     * </p>
     * <p>
     * If this LoginModule's own authentication attempt succeeded (checked by retrieving the private
     * state saved by the <code>login</code> method), then this method associates a number of
     * <code>NTPrincipal</code>s with the <code>Subject</code> located in the
     * <code>LoginModule</code>. If this LoginModule's own authentication attempted failed, then
     * this method removes any state that was originally saved.
     * </p>
     *
     * @return true if this LoginModule's own login and commit attempts succeeded, or false otherwise.
     * @exception LoginException if the commit fails.
     */
    @Override
    public boolean commit() throws LoginException {
        logger.debug("commit()");
        if (pending == null) {
            return false;
        }
        principals = new ArrayList<Principal>();
        for (Principal p : pending) {
            putPrincipal(subject.getPrincipals(), p);
        }
        commitSucceeded = true;
        return true;
    }

    /**
     * <p>
     * This method is called if the LoginContext's overall authentication failed. (the relevant
     * REQUIRED, REQUISITE, SUFFICIENT and OPTIONAL LoginModules did not succeed).
     * <p>
     * If this LoginModule's own authentication attempt succeeded (checked by retrieving the private
     * state saved by the <code>login</code> and <code>commit</code> methods), then this method
     * cleans up any state that was originally saved.
     * <p>
     *
     * @exception LoginException if the abort fails.
     * @return false if this LoginModule's own login and/or commit attempts failed, and true otherwise.
     */
    @Override
    public boolean abort() throws LoginException {
        logger.debug("abort()");
        if (pending.isEmpty()) {
            return false;
        } else if (!pending.isEmpty() && !commitSucceeded) {
            pending = new ArrayList<Principal>();
        } else {
            logout();
        }
        return true;
    }

    /**
     * Logout the user.
     * <p>
     * This method removes the <code>Principal</code>s that were added by the <code>commit</code>
     * method.
     * </p>
     *
     * @return true in all cases since this <code>LoginModule</code> should not be ignored.
     * @exception LoginException if the logout fails.
     */
    @Override
    public boolean logout() throws LoginException {
        logger.debug("logout()");
        commitSucceeded = false;
        // Remove all the principals we added
        for (Principal p : principals) {
            subject.getPrincipals().remove(p);
        }
        pending = null;
        principals = null;
        return true;
    }

    /**
     * Get a String option from the module's options.
     *
     * @param name Name of the option
     * @param dflt Default value for the option
     * @return The String value of the options object.
     */
    public String getOption(String name, String dflt) {
        String opt = (String) options.get(name);
        return opt == null ? dflt : opt;
    }

    /**
     * Get a boolean option from the module's options.
     *
     * @param name Name of the option
     * @param dflt Default value for the option
     * @return The boolean value of the options object.
     */
    protected boolean getOption(String name, boolean dflt) {
        String opt = ((String) options.get(name));
        if (opt == null) return dflt;
        opt = opt.trim();
        if (opt.equalsIgnoreCase("true") || opt.equalsIgnoreCase("yes") || opt.equals("1")) {
            return true;
        } else if (opt.equalsIgnoreCase("false") || opt.equalsIgnoreCase("no") || opt.equals("0")) {
            return false;
        } else {
            return dflt;
        }
    }

    /**
     * Get a numeric option from the module's options.
     *
     * @param name Name of the option
     * @param dflt Default value for the option
     * @return The boolean value of the options object.
     */
    public int getOption(String name, int dflt) {
        String opt = ((String) options.get(name));
        if (opt == null) return dflt;
        try {
            dflt = Integer.parseInt(opt);
        } catch (Exception e) {
            logger.info("Failed reading option.", e);
        }
        return dflt;
    }

    /**
     * Helper method to get the User principal from the Subject.
     * @param subject
     * @return
     */
    public static User getUser(Subject subject) {
        if (subject != null) {
            Set<User> userSet = subject.getPrincipals(User.class);
            if (userSet != null && !userSet.isEmpty()) {
                return userSet.iterator().next();
            }
        }
        return null;
    }

}
