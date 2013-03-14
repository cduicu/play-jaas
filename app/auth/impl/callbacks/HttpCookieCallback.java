package auth.impl.callbacks;

import play.mvc.Http;
import play.mvc.Http.Cookie;

public class HttpCookieCallback extends HeadlessCallback {

    private String parmVal;
    private String parmName;

    public HttpCookieCallback(String name) {
        this.parmName = name;
    }

    @Override
    public void process() {
        Http.Request req = getOriginalRequest();
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
