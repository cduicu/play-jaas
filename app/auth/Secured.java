package auth;

import javax.security.auth.Subject;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import play.mvc.Http;
import play.mvc.Http.Context;
import play.mvc.Result;
import play.mvc.Security;
import auth.controllers.Authentication;
import auth.impl.AbstractAuthModule;
import auth.models.User;

/**
 * The annotation to be used to secure controllers. <br>
 * TODO: pass the name of the authentication module in annotation to allow different authentication
 * schemes per project (for instance to differentiate between headless and UI calls)
 */
public class Secured extends Security.Authenticator {

    private static Logger logger = LoggerFactory.getLogger(Secured.class);

    @Override
    public String getUsername(Context ctx) {
        if (Configuration.getInstance().authnHandler == Configuration.HANDLER_NO_AUTH) {
            return Configuration.HANDLER_NO_AUTH;
        }
        User user = getCurrentUser(ctx);
        return (user != null) ? user.name : null;
    }

    @Override
    public Result onUnauthorized(Context ctx) {
        String authMethod = Configuration.getInstance().authnMethod;
        logger.debug("Authentication method: " + authMethod);
        if (authMethod.equals(Configuration.AUTH_METHOD_ACTIVE)) {
            return Authentication.login(ctx); // try to login automatically
        } else {
            return ok(views.html.notSignedIn.render());
        }
    }

    public static User getCurrentUser(Context ctx) {
        if (ctx == null)
            return null;
        Http.Session session = ctx.session();
        Subject subject = getSubject(session);
        return AbstractAuthModule.getUser(subject);
    }

    public static Subject getSubject(Http.Session session) {
        WebSession s = WebSession.getSession(session);
        if (s == null) {
            logger.info("No session found for this request.");
            return null;
        }
        return (Subject) s.get("user");
    }

}