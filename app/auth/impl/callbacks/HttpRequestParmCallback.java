package auth.impl.callbacks;

import play.data.DynamicForm;
import play.data.Form;
import play.mvc.Http;
import play.mvc.Http.Context;

public class HttpRequestParmCallback extends HeadlessCallback {

    private String parmVal;
    private String parmName;

    public HttpRequestParmCallback(String name) {
        this.parmName = name;
    }

    @Override
    public void process() {
        Context.current.set(getOriginalContext());
        Http.Request req = getOriginalRequest();
        if (req.method().compareToIgnoreCase("get") == 0) {
            if (req.queryString().get(parmName) != null) {
                parmVal = req.queryString().get(parmName)[0];
            }
        } else if (req.method().compareToIgnoreCase("post") == 0) {
            DynamicForm frm = Form.form().bindFromRequest();
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
