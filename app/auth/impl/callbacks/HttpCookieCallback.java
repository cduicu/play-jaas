package auth.impl.callbacks;

import play.mvc.Http;
import play.mvc.Http.Cookie;
import play.mvc.Http.Request;

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
