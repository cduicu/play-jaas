//==========================================================================
// $Id: HttpRequestParmCallback.java,v 0.1 Oct 30, 2012 2:24:57 PM cristiand Exp $
// (@) Copyright Sigma Systems (Canada)
// * Based on CVS log
//==========================================================================
package auth.impl.callbacks;

import play.mvc.Http;
import play.mvc.Http.Cookie;
import play.mvc.Http.Request;

/**
 * @version $Revision: $
 * @author $Author: cristiand $
 * @since $Date: Oct 30, 2012 $
 */
public class HttpCookieCallback implements IHeadlessCallback {

    private String parmVal;
    private String parmName;
    private Request req;

    public HttpCookieCallback(Http.Request req, String name) {
        this.req = req;
        this.parmName = name;
    }

    @Override
    public void process() {
        Cookie c = req.cookies().get(parmName);
        if (c!= null) parmVal = c.value();
    }

    public String getValue() {
        return parmVal;
    }

    public String getName() {
        return parmName;
    }

}
