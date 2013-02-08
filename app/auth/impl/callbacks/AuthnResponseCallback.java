package auth.impl.callbacks;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Subject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import play.data.DynamicForm;
import play.data.Form;
import play.mvc.Http;
import play.mvc.Http.Request;

import auth.utils.SAMLUtils;

public class AuthnResponseCallback implements IHeadlessCallback {

    private static Logger logger = LoggerFactory.getLogger(AuthnResponseCallback.class);
    private static final String SAML_RESPONSE = "SAMLResponse";
    private static final String RELAY_STATE   = "RelayState";
    private String errMsg = null;
    private Map<String,String> attrs = new HashMap<String, String>(); // output attributes
    private SAMLUtils samlUtils;
    private Request req;
    private boolean processed = false;
    private String relayState = null;

    /**
     * @param samlUtils
     * @param attrs2
     */
    public AuthnResponseCallback(Http.Request req, SAMLUtils samlUtils) {
        this.samlUtils = samlUtils;
        this.req = req;
    }

    public String getAttribute(String attrNm) {
        return attrs.get(attrNm);
    }

    public boolean isResponseProcessed() {
        return processed;
    }

    public String getRelayState() {
        return relayState;
    }

    /* (non-Javadoc)
     * @see auth.impl.callbacks.IHeadlessCallback#process()
     */
    @Override
    public void process() {
        DynamicForm frm = Form.form().bindFromRequest();
        String samlResponse = null;
        if (req.queryString().get(SAML_RESPONSE) != null) {
            samlResponse = req.queryString().get(SAML_RESPONSE)[0];
        } else {
            samlResponse = frm.get(SAML_RESPONSE);
        }
        //String relayState = null;
        if (req.queryString().get(RELAY_STATE) != null) {
            relayState = req.queryString().get(RELAY_STATE)[0];
        } else {
            relayState = frm.get(RELAY_STATE);
        }
        if (samlResponse == null || relayState == null) return;

        Response resp = samlUtils.decodeSAMLResponse(samlResponse);
        List<Assertion> assertions = samlUtils.decodeAssertions(resp);
        Subject subject = null;
        if (assertions.size() != 1) {
            errMsg = "FAILURE! Expected 1 assertion back; received: " + assertions.size();
            logger.warn(errMsg);
            return;
        }
        // I expect only one assertion here actually
        Assertion a = assertions.get(0);
        subject = a.getSubject();
        if (subject == null) {
            errMsg = "FAILURE! Subject is not present in assertion!";
            logger.warn(errMsg);
            return;
        }

        if (!samlUtils.processConditions(a.getConditions())) {
            errMsg = "FAILURE! User does not match IdP conditions!";
            logger.warn(errMsg);
            return;
        }

        String username = subject.getNameID().getValue();
        logger.info("User '" + username + "' successfully authenticated by IdP!");

        attrs.putAll(samlUtils.getAttributeValue(resp, username));
        if (attrs.isEmpty()) {
            errMsg = "FAILURE! Could not find value for attribute username!";
            logger.warn(errMsg);
            return;
        }
        logger.debug("Attributes: " + attrs);
        processed = true;
    }

}
