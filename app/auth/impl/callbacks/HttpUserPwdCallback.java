package auth.impl.callbacks;

import play.data.DynamicForm;
import play.data.Form;
import play.mvc.Http;
import play.mvc.Http.Request;
import auth.models.UserToken;

public class HttpUserPwdCallback implements IHeadlessCallback {

    public String              username;
    public String              password;
    public String              tkn;
    private Request            req;

    public static final String REQ_PARM_USERNAME = "username";
    public static final String REQ_PARM_PASSWORD = "password";
    public static final String REQ_PARM_TOKEN    = "token";

    public HttpUserPwdCallback(Http.Request req) {
        this.req = req;
    }

    @Override
    public void process() {
        if (req.method().compareToIgnoreCase("get") == 0) {
            if (req.queryString().get(REQ_PARM_TOKEN) != null) {
                tkn = req.queryString().get(REQ_PARM_TOKEN)[0];
                UserToken ut = UserToken.createUserToken(tkn, req);
                if (ut != null) {
                    username = ut.name;
                    password = ut.password;
                    return;
                }
            }
            if (req.queryString().get(REQ_PARM_USERNAME) != null) {
                username = req.queryString().get(REQ_PARM_USERNAME)[0];
            }
            if (req.queryString().get(REQ_PARM_PASSWORD) != null) {
                password = req.queryString().get(REQ_PARM_PASSWORD)[0];
            }
        } else if (req.method().compareToIgnoreCase("post") == 0) {
            DynamicForm frm = Form.form().bindFromRequest();
            tkn = frm.get(REQ_PARM_TOKEN);
            if (tkn != null) {
                UserToken ut = UserToken.createUserToken(tkn, req);
                if (ut != null) {
                    username = ut.name;
                    password = ut.password;
                    return;
                }
            }
            username = frm.get(REQ_PARM_USERNAME);
            password = frm.get(REQ_PARM_PASSWORD);
        }
    }

}
