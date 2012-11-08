//==========================================================================
// $Id: Confidential.java,v 0.1 Nov 8, 2012 2:53:05 PM cristiand Exp $
// (@) Copyright Sigma Systems (Canada)
// * Based on CVS log
//==========================================================================
package controllers;

import javax.security.auth.Subject;

import auth.Secured;
import auth.WebSession;
import auth.models.User;
import play.mvc.Result;
import play.mvc.Controller;
import play.mvc.Security;

/**
 * @version $Revision: $
 * @author $Author: cristiand $
 * @since $Date: Nov 8, 2012 $
 */
@Security.Authenticated(Secured.class)
public class Confidential extends Controller {

    public static Result test() {
        WebSession w = WebSession.getSession(session());
        User user = Secured.getCurrentUser(ctx());
        return ok(views.html.confidential.render(user));
    }

}
