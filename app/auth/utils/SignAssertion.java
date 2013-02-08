package auth.utils;

import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.security.SecurityConfiguration;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureException;
import org.opensaml.xml.signature.Signer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SignAssertion {
    private final static Logger logger               = LoggerFactory.getLogger(SignAssertion.class);
    final static Signature      signature            = null;
    final static String         password             = "secret";
    final static String         certificateAliasName = "selfsigned";
    final static String         fileName             = "idpcert.jks";

    private Credential getCredential(String fileName, String password, String certificateAliasName) {
        try {
            KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
            FileInputStream fis = new FileInputStream(fileName);
            ks.load(fis, password.toCharArray());
            fis.close();
            KeyStore.PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry) ks.getEntry(
                    certificateAliasName, new KeyStore.PasswordProtection(password.toCharArray()));
            PrivateKey pk = pkEntry.getPrivateKey();
            X509Certificate certificate = (X509Certificate) pkEntry.getCertificate();
            BasicX509Credential credential = new BasicX509Credential();
            credential.setEntityCertificate(certificate);
            credential.setPrivateKey(pk);
            return credential;
        } catch (Exception e) {
            logger.error("Failed getting the credential from KeyStore: " + fileName, e);
        }
        return null;
    }

    public static void main(String args[]) throws Exception {
        SignAssertion sign = new SignAssertion();
        Credential signingCredential = sign.getCredential(SignAssertion.fileName, SignAssertion.password,
                SignAssertion.certificateAliasName);
        Signature signature = null;
        try {
            DefaultBootstrap.bootstrap();
        } catch (ConfigurationException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        signature = (Signature) Configuration.getBuilderFactory().getBuilder(Signature.DEFAULT_ELEMENT_NAME)
                .buildObject(Signature.DEFAULT_ELEMENT_NAME);

        signature.setSigningCredential(signingCredential);

        // This is also the default if a null SecurityConfiguration is specified
        SecurityConfiguration secConfig = Configuration.getGlobalSecurityConfiguration();
        // If null this would result in the default KeyInfoGenerator being used
        //String keyInfoGeneratorProfile = "XMLSignature";

        try {
            SecurityHelper.prepareSignatureParams(signature, signingCredential, secConfig, null);
        } catch (SecurityException e) {
            e.printStackTrace();
        } catch (org.opensaml.xml.security.SecurityException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        //Response resp = SAMLWriter.getSamlAssertion();

//        resp.setSignature(signature);
//
//        try {
//            Configuration.getMarshallerFactory().getMarshaller(resp).marshall(resp);
//        } catch (MarshallingException e) {
//            e.printStackTrace();
//        }

        try {
            Signer.signObject(signature);
        } catch (SignatureException e) {
            e.printStackTrace();
        }

//        ResponseMarshaller marshaller = new ResponseMarshaller();
//        Element plain = marshaller.marshall(resp);
//        // response.setSignature(sign);
//        String samlResponse = XMLHelper.nodeToString(plain);
//        logger.info("********************\n*\n***********::" + samlResponse);

    }
}
