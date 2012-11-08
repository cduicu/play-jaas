//==========================================================================
// $Id: HttpRequestParmCallback.java,v 0.1 Oct 30, 2012 2:24:57 PM cristiand Exp $
// (@) Copyright Sigma Systems (Canada)
// * Based on CVS log
//==========================================================================
package auth.impl.callbacks;

import play.mvc.Http;
import play.mvc.Http.Request;

/**
 * @version $Revision: $
 * @author $Author: cristiand $
 * @since $Date: Oct 30, 2012 $
 */
public class HttpRequestHeaderCallback implements IHeadlessCallback {

    private String parmVal;
    private String parmName;
    private Request req;

    public HttpRequestHeaderCallback(Http.Request req, String name) {
        this.req = req;
        this.parmName = name;
    }

    public String getValue() {
        return parmVal;
    }

    public String getName() {
        return parmName;
    }

    /* (non-Javadoc)
     * @see auth.impl.callbacks.IHeadlessCallback#process()
     */
    @Override
    public void process() {
        parmVal = req.getHeader(parmName);
    }

}
