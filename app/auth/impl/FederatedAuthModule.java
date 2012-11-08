//==========================================================================
// $Id: FederatedAuthModele.java,v 0.1 Nov 3, 2012 3:11:30 PM cristiand Exp $
// (@) Copyright Sigma Systems (Canada)
// * Based on CVS log
//==========================================================================
package auth.impl;

import java.security.Principal;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.LoginException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import play.mvc.Controller;
import play.mvc.Http;
import play.mvc.Http.Context;
import play.mvc.Result;
import auth.WebSession;
import auth.impl.callbackHandlers.SAML2CallbackHandler;
import auth.impl.callbacks.AuthnResponseCallback;
import auth.models.User;
import auth.models.UserToken;
import auth.utils.SAMLUtils;

/**
 * I am passing information from the login() to the onAuthSucceeded() via a fake principal PendingPrincipal.
 * TODO: is there a better way?
 *
 * @version $Revision: $
 * @author $Author: cristiand $
 * @since $Date: Nov 3, 2012 $
 */
public class FederatedAuthModule extends AbstractAuthModule {

    private static Logger       logger                = LoggerFactory.getLogger(FederatedAuthModule.class);
    private static final String FEDERATED_AUTH_MODULE = "FederatedAuth";
    private static final String TOKEN_PASSWORD        = "cangetin";

    // configuration
    public String idpUrl;                       // url where we send AuthnRequest
    private String derFile;                      // needed when messages are signed
    private String pemFile;                      // needed when messages are signed
    private String samlIssuerUrl;                // must match the entityID from the SP's metadata description
    private String assertionConsumerServiceUrl;  // must match the <AssertionConsumerService>
    private String idpSoapUrl;                   // url where we send AttributeQuery
    private String samlUsername;                 // the attribute I look for in response
    private SAMLUtils samlUtils;

    /**
     * @version $Revision: $
     * @author $Author: cristiand $
     * @since $Date: Nov 6, 2012 $
     */
    public class PendingPrincipal implements Principal {

        private Map<String,String> principalAttrs = new HashMap<String, String>();
        private String nameAttr;

        /**
         * @param idpUrl
         */
        public PendingPrincipal(String nameAttr) {
            this.nameAttr = nameAttr;
        }

        public void setAttribute(String nm, String value) {
            principalAttrs.put(nm, value);
        }

        /* (non-Javadoc)
         * @see java.security.Principal#getName()
         */
        @Override
        public String getName() {
            return getAttribute(nameAttr);
        }

        public String getAttribute(String nm) {
            return principalAttrs.get(nm);
        }

    }

    /* (non-Javadoc)
     * @see auth.IAuthModule#getCallbackHandler(play.mvc.Http.Context)
     */
    @Override
    public CallbackHandler getCallbackHandler(Context ctx) {
        return new SAML2CallbackHandler();
    }

    /* (non-Javadoc)
     * @see auth.IAuthModule#getModuleName()
     */
    @Override
    public String getModuleName() {
        return FEDERATED_AUTH_MODULE;
    }

    /* (non-Javadoc)
     * @see javax.security.auth.spi.LoginModule#login()
     */
    @Override
    public boolean login() throws LoginException {
        logger.debug("login()");
        if (callbackHandler == null) {
            throw new LoginException("Error: no CallbackHandler available!");
        }
        Http.Request req = Context.current.get().request(); // I'm counting on having been set
                                                            // before calling login
        ArrayList<Callback> callbacks = new ArrayList<Callback>();
        callbacks.add(new AuthnResponseCallback(req, samlUtils));
        try {
            // handle callbacks
            Callback[] cb = new Callback[callbacks.size()];
            callbackHandler.handle(callbacks.toArray(cb));

            // process callbacks results
            boolean respProcessed = ((AuthnResponseCallback)cb[0]).isResponseProcessed();

            pending = new ArrayList<Principal>();
            if (!respProcessed) {
                // this is step 1 - create and send AuthnRequest
                PendingPrincipal p = new PendingPrincipal("idpUrl");
                p.setAttribute("idpUrl", idpUrl);
                p.setAttribute("samlIssuerUrl", samlIssuerUrl);
                p.setAttribute("assertionConsumerServiceUrl", assertionConsumerServiceUrl);
                pending.add(p);
                // even though it returns true, the user is not considered authenticated (see commit())
                return true;
            } else {
                // step 2 - processed AuthResponse, extract username
                String userid = ((AuthnResponseCallback)cb[0]).getAttribute(samlUsername);
                String relayState = ((AuthnResponseCallback)cb[0]).getRelayState();
                if (userid != null) {
                    User user = UserToken.createUserToken(userid, TOKEN_PASSWORD, req);
                    user.fullName = userid;
                    //user.email = email; user.phone = phone;
                    pending.add(user);

                    PendingPrincipal p = new PendingPrincipal("RelayState");
                    p.setAttribute("RelayState", relayState);
                    pending.add(p);
                    return true;
                } else {
                    logger.info("Attribute " + samlUsername + " not retrieved from IdP");
                }
            }
        } catch (Exception e) {
            logger.info("failed user validation.", e);
        }
        return false;
    }

    /*
     * (non-Javadoc)
     *
     * @see controllers.auth.IAuthenticator#onAuthSucceeded(models.User)
     */
    @Override
    public Result onAuthSucceeded(javax.security.auth.Subject subject) {
        User user = getUser(subject);
        if (user == null) {
            // step 1 - send AuthnRequest
            Set<PendingPrincipal> plst = subject.getPrincipals(PendingPrincipal.class);
            PendingPrincipal p = plst.iterator().next();
            String idpUrl = p.getName();
            String issuerUrl = p.getAttribute("samlIssuerUrl");
            String consumerUrl = p.getAttribute("assertionConsumerServiceUrl");

            SAMLUtils samlUtils = SAMLUtils.getInstance();
            String samlRequest = samlUtils.buildAuthnRequest(issuerUrl, consumerUrl, false);
            String relayState = Context.current().request().uri();// ctx.request().uri();
            return Controller.ok(views.html.samlRequestAuthn.render(idpUrl, samlRequest, relayState));
        } else {
            Set<PendingPrincipal> plst = subject.getPrincipals(PendingPrincipal.class);
            PendingPrincipal p = plst.iterator().next();
            String relayState = p.getName();
            logger.info("User '" + user.name + "' successfully signed in! Redirecting to " + relayState);
            WebSession session = WebSession.newSession(Context.current().session());
            session.put("user", subject);
            return Controller.redirect(relayState);
        }
    }

    @Override
    public void initialize(javax.security.auth.Subject subject, CallbackHandler callbackHandler,
            Map<String, ?> sharedState, Map<String, ?> options) {
        super.initialize(subject, callbackHandler, sharedState, options);
        idpUrl = getOption("idpUrl", null);
        if (idpUrl == null) {
            logger.error("idpUrl must be specified in JAAS configuration file");
        }
        assertionConsumerServiceUrl = getOption("assertionConsumerServiceUrl", null);
        if (assertionConsumerServiceUrl == null) {
            logger.error("assertionConsumerServiceUrl must be specified in JAAS configuration file");
        }
        samlIssuerUrl = getOption("samlIssuerUrl", null);
        if (samlIssuerUrl == null) {
            logger.error("samlIssuerUrl must be specified in JAAS configuration file");
        }
        samlUsername = getOption("userAttr", null);
        if (samlUsername == null) {
            logger.error("samlUsername must be specified in JAAS configuration file");
        }
        idpSoapUrl = getOption("idpSoapUrl", null);
        pemFile = getOption("pemFile", null);
        derFile = getOption("derFile", null);
        boolean debug = getOption("debug", false);
        logger.debug("idpUrl=" + idpUrl + "; consumerUrl=" + assertionConsumerServiceUrl + "; issuer="
                + samlIssuerUrl + "; userAttr=" + samlUsername + "; idPSoap=" + idpSoapUrl + "; pemFile="
                + pemFile + "; derFile=" + derFile);
        samlUtils = SAMLUtils.getInstance();
        samlUtils.setDERFileNm(derFile);
        samlUtils.setPEMFileNm(pemFile);
        samlUtils.setIdpSoapUrl(idpSoapUrl);
        samlUtils.setPEMFileNm(samlIssuerUrl);
        samlUtils.setSamlUsername(samlUsername);
        samlUtils.setDebug(debug);
    }

}
