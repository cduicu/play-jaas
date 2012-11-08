//==========================================================================
// $Id: HttpRequestParmCallback.java,v 0.1 Oct 30, 2012 2:24:57 PM cristiand Exp $
// (@) Copyright Sigma Systems (Canada)
// * Based on CVS log
//==========================================================================
package auth.impl.callbacks;

import play.data.DynamicForm;
import play.mvc.Controller;
import play.mvc.Http;
import play.mvc.Http.Request;

/**
 * @version $Revision: $
 * @author $Author: cristiand $
 * @since $Date: Oct 30, 2012 $
 */
public class HttpRequestParmCallback implements IHeadlessCallback {

    private String parmVal;
    private String parmName;
    private Request req;


    public HttpRequestParmCallback(Http.Request req, String name) {
        this.req = req;
        this.parmName = name;
    }

    @Override
    public void process() {
        if (req.method().compareToIgnoreCase("get") == 0) {
            if (req.queryString().get(parmName) != null) {
                parmVal = req.queryString().get(parmName)[0];
            }
        } else if (req.method().compareToIgnoreCase("post") == 0) {
            DynamicForm frm = Controller.form().bindFromRequest();
            parmVal = frm.get(parmName);
        }
    }

    public String getValue() {
        return parmVal;
    }

    public String getName() {
        return parmName;
    }

}
