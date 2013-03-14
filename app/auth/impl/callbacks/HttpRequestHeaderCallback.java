package auth.impl.callbacks;

import play.mvc.Http;

public class HttpRequestHeaderCallback extends HeadlessCallback {

    private String parmVal;
    private String parmName;

    public HttpRequestHeaderCallback(String name) {
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
        Http.Request req = getOriginalRequest();
        parmVal = req.getHeader(parmName);
    }

}
