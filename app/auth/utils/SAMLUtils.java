package auth.utils;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.security.KeyFactory;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.SAMLVersion;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeQuery;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml2.core.AuthnContextComparisonTypeEnumeration;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Conditions;
import org.opensaml.saml2.core.EncryptedAssertion;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.NameIDPolicy;
import org.opensaml.saml2.core.RequestedAuthnContext;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.Subject;
import org.opensaml.saml2.encryption.Decrypter;
import org.opensaml.ws.soap.common.SOAPObjectBuilder;
import org.opensaml.ws.soap.soap11.Body;
import org.opensaml.ws.soap.soap11.Envelope;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.XMLObjectBuilder;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.encryption.InlineEncryptedKeyResolver;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallerFactory;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.parse.ParserPool;
import org.opensaml.xml.security.SecurityConfiguration;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.keyinfo.StaticKeyInfoCredentialResolver;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.signature.SignableXMLObject;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.Signer;
import org.opensaml.xml.util.Base64;
import org.opensaml.xml.util.XMLHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

public class SAMLUtils {

    private static Logger logger = LoggerFactory.getLogger(SAMLUtils.class);
    private static SAMLUtils         instance;
    private ParserPool              parserPool;
    private XMLObjectBuilderFactory builderFactory;
    private MarshallerFactory       marshallerFactory;
    private UnmarshallerFactory     unmarshallerFactory;
    private String derFile;
    private String pemFile;
    private String samlIssuerUrl;
    private String idpSoapUrl;
    private String samlUsername;
    private boolean debug;

    public static final String      ATTR_DER_FILE     = "derFile";
    public static final String      ATTR_PEM_FILE     = "pemFile";
    public static final String      ATTR_ISSUER       = "samlIssuerUrl";
    public static final String      ATTR_IDP_SOAP_URL = "idpSoapUrl";
    public static final String      ATTR_USERNAME     = "samlUsername";

    private SAMLUtils() {
    }

    public static final SAMLUtils getInstance() {
        if (instance == null) {
            synchronized (SAMLUtils.class) {
                instance = new SAMLUtils();
                try {
                    instance.init();
                } catch (ConfigurationException e) {
                    logger.error("Can't initialize openSAML!", e);
                }
            }
        }
        return instance;
    }

    private void init() throws ConfigurationException {
        DefaultBootstrap.bootstrap();
        parserPool = new BasicParserPool();
        builderFactory = Configuration.getBuilderFactory();
        marshallerFactory = Configuration.getMarshallerFactory();
        unmarshallerFactory = Configuration.getUnmarshallerFactory();
    }

    public void setDERFileNm(String der) {
        this.derFile = der;
    }

    public void setPEMFileNm(String pem) {
        this.pemFile = pem;
    }

    public void setSamlIssuerUrl(String issuer) {
        this.samlIssuerUrl = issuer;
    }

    public void setIdpSoapUrl(String idpSoap) {
        this.idpSoapUrl = idpSoap;
    }

    public void setSamlUsername(String usernm) {
        this.samlUsername = usernm;
    }

    /**
     * Build the AuthnRequest message.
     *
     * @param forceAuthn
     * @return
     */
    public String buildAuthnRequest(String samlIssuerUrl, String assertionConsumerServiceUrl, boolean forceAuthn) {
        //logger.debug("issuer: " + samlIssuerUrl + "; consumer: " + assertionConsumerServiceUrl);
        XMLObjectBuilder issuerBuilder = builderFactory.getBuilder(Issuer.DEFAULT_ELEMENT_NAME);
        Issuer issuer = (Issuer) issuerBuilder.buildObject(Issuer.DEFAULT_ELEMENT_NAME);
        issuer.setValue(samlIssuerUrl);

        // Create NameIDPolicy
        XMLObjectBuilder nameIdPolicyBuilder = builderFactory.getBuilder(NameIDPolicy.DEFAULT_ELEMENT_NAME);
        NameIDPolicy nameIdPolicy = (NameIDPolicy) nameIdPolicyBuilder.buildObject(NameIDPolicy.DEFAULT_ELEMENT_NAME);
        nameIdPolicy.setFormat(NameID.TRANSIENT);
        nameIdPolicy.setSPNameQualifier(samlIssuerUrl);
        nameIdPolicy.setAllowCreate(true);

        // Create AuthnContextClassRef
        XMLObjectBuilder authnContextClassRefBuilder = builderFactory
                .getBuilder(AuthnContextClassRef.DEFAULT_ELEMENT_NAME);
        AuthnContextClassRef authnContextClassRef = (AuthnContextClassRef) authnContextClassRefBuilder
                .buildObject(AuthnContextClassRef.DEFAULT_ELEMENT_NAME);
        authnContextClassRef.setAuthnContextClassRef(AuthnContext.PPT_AUTHN_CTX);

        // Create RequestedAuthnContext
        XMLObjectBuilder requestedAuthnContextBuilder = builderFactory
                .getBuilder(RequestedAuthnContext.DEFAULT_ELEMENT_NAME);
        RequestedAuthnContext requestedAuthnContext = (RequestedAuthnContext) requestedAuthnContextBuilder
                .buildObject(RequestedAuthnContext.DEFAULT_ELEMENT_NAME);
        requestedAuthnContext.setComparison(AuthnContextComparisonTypeEnumeration.EXACT);
        requestedAuthnContext.getAuthnContextClassRefs().add(authnContextClassRef);

        XMLObjectBuilder authnRequestBuilder = builderFactory.getBuilder(AuthnRequest.DEFAULT_ELEMENT_NAME);
        AuthnRequest authRequest = (AuthnRequest) authnRequestBuilder.buildObject(AuthnRequest.DEFAULT_ELEMENT_NAME);
        authRequest.setForceAuthn(forceAuthn);
        authRequest.setIsPassive(false);
        authRequest.setIssueInstant(new DateTime());
        authRequest.setProtocolBinding(SAMLConstants.SAML2_POST_BINDING_URI);
        authRequest.setAssertionConsumerServiceURL(assertionConsumerServiceUrl);
        authRequest.setIssuer(issuer);
        authRequest.setNameIDPolicy(nameIdPolicy);
        authRequest.setRequestedAuthnContext(requestedAuthnContext);
        authRequest.setID(java.util.UUID.randomUUID().toString());
        authRequest.setVersion(SAMLVersion.VERSION_20);

        // Now we must build our representation to put into the html form to be submitted to the idp
        Marshaller marshaller = marshallerFactory.getMarshaller(AuthnRequest.DEFAULT_ELEMENT_NAME);
        org.w3c.dom.Element authDOM = null;
        try {
            authDOM = marshaller.marshall(authRequest);
        } catch (MarshallingException e) {
            logger.error("Failed marshalling the xml", e);
            return null;
        }
        StringWriter rspWrt = new StringWriter();
        XMLHelper.writeNode(authDOM, rspWrt);
        String messageXML = rspWrt.toString();
        saveToFile("AuthnRequest.xml", messageXML);
        return Base64.encodeBytes(messageXML.getBytes());
    }

    public List<Assertion> decodeAssertions(Response resp) {
        ArrayList<Assertion> assertions = new ArrayList<Assertion>();
        try {
            logger.trace("AuthnResponse Assertions=" + resp.getAssertions().size() + "; EncryptedAssertions="
                    + resp.getEncryptedAssertions().size());
            for (Assertion assertion : resp.getAssertions()) {
                assertions.add(assertion);
            }
            int i = 0;
            for (EncryptedAssertion encryptedAssertion : resp.getEncryptedAssertions()) {
                Assertion assertion = decodeAssertion(encryptedAssertion);
                assertions.add(assertion);
                saveToFile("DecodedAuthnAssertion" + i++ + ".xml", assertion);
            }
        } catch (Exception e) {
            logger.error("failed decoding SAMLResponse", e);
        }
        return assertions;
    }

    public Response decodeSAMLResponse(String samlResponse) {
        try {
            byte[] decodedBytes = Base64.decode(samlResponse);
            ByteArrayInputStream bytesIn = new ByteArrayInputStream(decodedBytes);
            // InflaterInputStream inflater = new InflaterInputStream(bytesIn, new Inflater());
            saveToFile("AuthnResponse.xml", decodedBytes);
            Document messageDoc = parserPool.parse(bytesIn);
            Element messageElem = messageDoc.getDocumentElement();
            // logger.info("DOM was:\n{}", XMLHelper.nodeToString(messageElem));
            Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(messageElem);
            if (unmarshaller == null) {
                logger.trace("Unable to unmarshall message, no unmarshaller registered for message element "
                        + XMLHelper.getNodeQName(messageElem));
            }
            Response resp = (Response) unmarshaller.unmarshall(messageElem);
            logger.trace("AuthnResponse StatusCode:" + resp.getStatus().getStatusCode().getValue());
            return resp;
        } catch (Exception e) {
            logger.error("failed decoding SAMLResponse", e);
        }
        return null;
    }

    private Assertion decodeAssertion(EncryptedAssertion encryptedAssertion) {
        try {
            Credential decryptionCredential = getCredential();
            StaticKeyInfoCredentialResolver skicr = new StaticKeyInfoCredentialResolver(decryptionCredential);
            Decrypter samlDecrypter = new Decrypter(null, skicr, new InlineEncryptedKeyResolver());
            return samlDecrypter.decrypt(encryptedAssertion);
        } catch (Exception e) {
            logger.error("failed decrypting assertion!", e);
        }
        return null;
    }

    private Credential getCredential() {
        BasicX509Credential credential = null;
        try {
            // read private key
            File privateKeyFile = new File(derFile);
            FileInputStream inputStreamPrivateKey = new FileInputStream(privateKeyFile);
            byte[] encodedPrivateKey = new byte[(int) privateKeyFile.length()];
            inputStreamPrivateKey.read(encodedPrivateKey);
            inputStreamPrivateKey.close();
            PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(encodedPrivateKey);
            RSAPrivateKey privateKey = (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(
                    privateKeySpec);
            // read the certificate
            InputStream inStream = new FileInputStream(pemFile);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(inStream);
            // create credential
            credential = new BasicX509Credential();
            credential.setEntityCertificate(cert);
            credential.setPrivateKey(privateKey);
        } catch (Exception e) {
            logger.error("failed getting credential!", e);
        }
        return credential;
    }

    private static String readInputStreamAsString(InputStream in) throws IOException {
        BufferedInputStream bis = new BufferedInputStream(in);
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        int result = bis.read();
        while (result != -1) {
            byte b = (byte) result;
            buf.write(b);
            result = bis.read();
        }
        return buf.toString();
    }

    public static String getXMLAsString(XMLObject obj) {
        Marshaller marshaller = Configuration.getMarshallerFactory().getMarshaller(obj);
        StringWriter rspWrt = new StringWriter();
        try {
            org.w3c.dom.Element domEl = marshaller.marshall(obj);
            XMLHelper.writeNode(domEl, rspWrt);
        } catch (MarshallingException e) {
            logger.error("Failed marshalling the XMLObject!", e);
        }
        return rspWrt.toString();
    }

    private AttributeQuery buildAttributeQuery(String name) {
        SAMLObjectBuilder<Issuer> issuerBuilder = (SAMLObjectBuilder<Issuer>) builderFactory
                .getBuilder(Issuer.DEFAULT_ELEMENT_NAME);
        Issuer issuer = issuerBuilder.buildObject();
        issuer.setFormat(NameID.ENTITY);
        issuer.setValue(samlIssuerUrl);

        SAMLObjectBuilder<NameID> nameIdBuilder = (SAMLObjectBuilder<NameID>) builderFactory
                .getBuilder(NameID.DEFAULT_ELEMENT_NAME);
        NameID nameId = nameIdBuilder.buildObject();
        nameId.setValue(name);

        SAMLObjectBuilder<Subject> subjectBuilder = (SAMLObjectBuilder<Subject>) builderFactory
                .getBuilder(Subject.DEFAULT_ELEMENT_NAME);
        Subject subject = subjectBuilder.buildObject();
        subject.setNameID(nameId);

        SAMLObjectBuilder<AttributeQuery> attributeQueryBuilder = (SAMLObjectBuilder<AttributeQuery>) builderFactory
                .getBuilder(AttributeQuery.DEFAULT_ELEMENT_NAME);
        AttributeQuery query = attributeQueryBuilder.buildObject();
        query.setID(java.util.UUID.randomUUID().toString());
        query.setIssueInstant(new DateTime());
        query.setIssuer(issuer);
        query.setSubject(subject);
        query.setVersion(SAMLVersion.VERSION_20);
        return query;
    }

    private String getSOAPMessage(AttributeQuery query) throws MarshallingException {
        SOAPObjectBuilder<Body> bodyBuilder = (SOAPObjectBuilder<Body>) builderFactory
                .getBuilder(Body.DEFAULT_ELEMENT_NAME);
        Body body = bodyBuilder.buildObject();
        body.getUnknownXMLObjects().add(query);

        SOAPObjectBuilder<Envelope> envelopeBuilder = (SOAPObjectBuilder<Envelope>) builderFactory
                .getBuilder(Envelope.DEFAULT_ELEMENT_NAME);
        Envelope envelope = envelopeBuilder.buildObject();
        envelope.setBody(body);

        Marshaller marshaller = marshallerFactory.getMarshaller(envelope);
        Element envelopeElem = marshaller.marshall(envelope);

        StringWriter writer = new StringWriter();
        XMLHelper.writeNode(envelopeElem, writer);
        return writer.toString();
    }

    private Response attributeQuery(String nameId) {
        try {
            AttributeQuery query = buildAttributeQuery(nameId);
            signRequest(query);
            String soapRequest = getSOAPMessage(query);
            saveToFile("AttrQueryRequest.xml", soapRequest);
            SendSoapMsg sender = new SendSoapMsg(idpSoapUrl);
            String soapResponse = sender.sendMsg(soapRequest);
            saveToFile("AttrQueryResponse.xml", soapResponse);

            ByteArrayInputStream bytes = new ByteArrayInputStream(soapResponse.getBytes());
            Document messageDoc = parserPool.parse(bytes);
            Element messageElem = messageDoc.getDocumentElement();

            Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(messageElem);
            Envelope envelope = (Envelope) unmarshaller.unmarshall(messageElem);
            Response resp = (Response) envelope.getBody().getOrderedChildren().get(0);
            return resp;
        } catch (Exception e) {
            logger.error("Failed retrieving attributes!", e);
        }
        return null;
    }

    private List<Attribute> getAttributesFromAssertions(List<Assertion> assertions) {
        ArrayList<Attribute> attrs = new ArrayList<Attribute>();
        for (Assertion assertion : assertions) {
            attrs.addAll(getAttributesFromAssertion(assertion));
        }
        return attrs;
    }

    private List<Attribute> getAttributesFromAssertion(Assertion assertion) {
        ArrayList<Attribute> attrs = new ArrayList<Attribute>();
        for (AttributeStatement stmt : assertion.getAttributeStatements()) {
            attrs.addAll(stmt.getAttributes());
        }
        return attrs;
    }

    private void saveToFile(String fileNm, String fileContent) {
        saveToFile(fileNm, fileContent.getBytes());
    }

    private void saveToFile(String fileNm, byte[] fileContent) {
        if (!debug) return;
        try {
            String filePath = new File(".").getAbsolutePath() + "\\public\\xmlSample\\";
            File f = new File(filePath + fileNm);
            if (f.exists()) {
                f.delete();
            }
            f.createNewFile();
            FileOutputStream fi = new FileOutputStream(f);
            fi.write(fileContent);
            fi.flush();
            fi.close();
        } catch (Exception e) {
            logger.error("Can't save to file", e);
        }
    }

    private void saveToFile(String fileNm, XMLObject obj) {
        Marshaller marshaller = marshallerFactory.getMarshaller(obj);
        org.w3c.dom.Element authDOM = null;
        try {
            authDOM = marshaller.marshall(obj);
        } catch (MarshallingException e) {
            logger.error("Failed marshalling the xml", e);
            return;
        }
        StringWriter rspWrt = new StringWriter();
        XMLHelper.writeNode(authDOM, rspWrt);
        String messageXML = rspWrt.toString();
        saveToFile(fileNm, messageXML.getBytes());
    }

    private void signRequest(SignableXMLObject obj) {
        Credential credential = getCredential();
        Signature signature = (Signature) Configuration.getBuilderFactory()
                .getBuilder(Signature.DEFAULT_ELEMENT_NAME).buildObject(Signature.DEFAULT_ELEMENT_NAME);
        signature.setSigningCredential(credential);

        SecurityConfiguration secConfig = Configuration.getGlobalSecurityConfiguration();
        try {
            SecurityHelper.prepareSignatureParams(signature, credential, secConfig, null);
            obj.setSignature(signature);
            Configuration.getMarshallerFactory().getMarshaller(obj).marshall(obj);
            Signer.signObject(signature);
        } catch (Exception e) {
            logger.error("Can't prepare signature", e);
        }
    }

    private void logAttributes(List<Attribute> attrs) {
        if (!debug) return;
        for (Attribute attr : attrs) {
            String s = "Attribute name=" + attr.getName() + "; friendlyName=" + attr.getFriendlyName()
                    + "; nameFormat=" + attr.getNameFormat() + "; values=" + attr.getAttributeValues().size()
                    + " [";
            for (XMLObject val : attr.getAttributeValues()) {
                s += "{qname:" + val.getElementQName() + ", qVal:" + val.getDOM().getNodeValue() + "}";
            }
            s += "]";
            logger.debug(s);
        }
    }

    public boolean processConditions(Conditions conditions) {
        // TODO
        return true;
    }

    public Map<String, String> getAttributeValue(Response authnResp, String nameId) {
        HashMap<String, String> attributes = new HashMap<String, String>();
        ArrayList<Attribute> attrs = new ArrayList<Attribute>();

        attrs.addAll(getAttributesFromAssertions(authnResp.getAssertions()));
        int i = 0;
        for (EncryptedAssertion encryptedAssertion : authnResp.getEncryptedAssertions()) {
            Assertion assertion = decodeAssertion(encryptedAssertion);
            saveToFile("DecodedAttrQueryAssertion" + i++ + ".xml", assertion);
            attrs.addAll(getAttributesFromAssertion(assertion));
        }
        logger.trace("Found " + attrs.size() + " attributes in the AuthnResponse");

        for (Attribute attr : attrs) {
            String nm = attr.getName() == null ? attr.getFriendlyName() : attr.getName();
            attributes.put(nm, attr.getAttributeValues().get(0).getDOM().getTextContent());
        }
        logAttributes(attrs);
        if (attributes.containsKey(samlUsername)) {
            return attributes;
        }

        logger.trace("Attribute '" + samlIssuerUrl + "' not found in AuthnResponse, make an AttributeQuery ...");
        Response resp = attributeQuery(nameId);
        String statusCode = resp.getStatus().getStatusCode().getValue();
        logger.trace("AttrQuery StatusCode:" + statusCode);
        if (!statusCode.equals(StatusCode.SUCCESS_URI)) {
            String statusMsg = resp.getStatus().getStatusMessage().getMessage();
            logger.info("AttrQuery FAILED! " + statusMsg);
        } else {
            logger.trace("AttrQuery Assertions=" + resp.getAssertions().size() + "; EncryptedAssertions="
                    + resp.getEncryptedAssertions().size());
            attrs.addAll(getAttributesFromAssertions(resp.getAssertions()));
            for (EncryptedAssertion encryptedAssertion : resp.getEncryptedAssertions()) {
                Assertion assertion = decodeAssertion(encryptedAssertion);
                attrs.addAll(getAttributesFromAssertion(assertion));
            }
            logger.trace("Received " + attrs.size() + " attributes from AttributeQuery response");
        }

        for (Attribute attr : attrs) {
            String nm = attr.getName() == null ? attr.getFriendlyName() : attr.getName();
            attributes.put(nm, attr.getAttributeValues().get(0).getDOM().getTextContent());
        }
        logAttributes(attrs);
        return attributes;
    }

    /**
     * @param debug
     */
    public void setDebug(boolean debug) {
        this.debug = debug;
    }


}
