package auth.utils;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;

import org.opensaml.xml.util.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SendSoapMsg {

    private static Logger logger = LoggerFactory.getLogger(SendSoapMsg.class);
    private boolean verbose = false;
    private String server, userName, password;

    public SendSoapMsg(String svr) {
        this(svr, null, null);
    }

    public SendSoapMsg(String svr, String usrNm, String pswd) {
        server = svr;
        userName = usrNm;
        password = pswd;
    }

    public boolean isVerbose() {
        return verbose;
    }

    public void setVerbose(boolean verbose) {
        this.verbose = verbose;
    }

    private void log(String str) {
        logger.info(str);
    }

    private HttpURLConnection getHttpConnection(String server, String userName, String password, long length) {
        HttpURLConnection httpConn = null;
        try {
            if (verbose) {
                log("Connecting to " + server + " (" + userName + "/" + password + ") ...");
            }
            URL u = new URL(server);
            URLConnection uc = u.openConnection();
            httpConn = (HttpURLConnection) uc;
            //httpConn.setRequestProperty("SOAPAction", SOAP_ACTION); // not really necessary...
            httpConn.setRequestProperty("Content-Length", String.valueOf(length));
            httpConn.setRequestProperty("Content-Type", "text/xml; charset=utf-8");
            httpConn.setDoInput(true);
            httpConn.setDoOutput(true);
            httpConn.setRequestMethod("POST");
            if (verbose) {
                log("HTTP request props: " + httpConn.getRequestProperties());
            }
            if (userName != null && password != null) {
                String userInfo = userName + ":" + password;
                //BASE64Encoder encoder = new BASE64Encoder();
                byte[] userInfoBytes = userInfo.getBytes(); // I18n bug here!
                String authInfo = "Basic " + Base64.encodeBytes(userInfoBytes);
                httpConn.setRequestProperty("Authorization", authInfo);
            }
            httpConn.connect();
            if (verbose) {
                log("HTTP connection established.  Sending soap request...");
            }
        } catch (Exception e) {
            if (verbose)
                e.printStackTrace();
            log(e.getMessage());
            httpConn = null;
        }
        return httpConn;
    }

    /**
     * Sends a soap message and returns the reply.
     * @param soapMsg
     * @return the reply from server as string
     */
    public String sendMsg(String soapMsg) {
        if (soapMsg == null) {
            log("Nothing to send!");
            return null;
        }
        String responseStr = null;
        long csu_startmillis = System.currentTimeMillis();
        HttpURLConnection connection = getHttpConnection(server, userName, password, soapMsg.length());
        if (connection == null) {
            return null;
        }
        try {
            // Get an output stream on the connection and create a writer
            OutputStream out = connection.getOutputStream();
            Writer wout = new OutputStreamWriter(out);

            // Get the start time
            long startmillis = System.currentTimeMillis();

            // Send the soap message using the HTTP connection
            wout.write(soapMsg);
            wout.flush();
            wout.close();

            // Print the soap request message to the console
            if (verbose) {
                log("SOAP Request Msg: \n" + soapMsg + "\n");
            }
            log("SOAP request message sent.  Waiting for response...");

            // Read the soap response
            InputStream in = connection.getInputStream();
            StringBuilder sb = new StringBuilder();
            byte[] b = new byte[4096];
            for (int n; (n = in.read(b)) != -1;) {
                sb.append(new String(b, 0, n));
            }
            responseStr = sb.toString();
            in.close();

            // Get send soap msg stop time and calculate elapsed time
            long endmillis = System.currentTimeMillis();
            long csu_elapsedTime = (startmillis - csu_startmillis);
            long elapsedTime = (endmillis - startmillis);
            if (verbose) {
                log("SOAP Response Msg: \n" + responseStr + "\n");
                log("HTTP setup: " + csu_elapsedTime + "ms ; soapRequest: " + elapsedTime + "ms");
            }
            connection.disconnect();
        } catch (IOException e) {
            e.printStackTrace(System.err);
        }
        return responseStr;
    }

    /***/
//    public static void main(String[] args) throws Exception {
//        String server = "http://torvm-core12.sigmasys.net:8080/idp/profile/SAML2/SOAP/AttributeQuery";
//        SendSoapMsg soapSender = new SendSoapMsg(server);
//        soapSender.setVerbose(true);
//
//        FileInputStream fi = new FileInputStream(
//                new File("C:\\home\\sso1\\public\\xmlSample\\SAMLAttributeQuery.xml"));
//        String s = SAMLUtil.readInputStreamAsString(fi);
//        String reply = soapSender.sendMsg(s);
//        System.out.println(reply);
//        soapSender.log("DONE!");
//    }

}
