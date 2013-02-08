package auth.models;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ning.http.util.Base64;

import play.mvc.Http;

public class UserToken extends User {

    private static Logger              logger   = LoggerFactory.getLogger(UserToken.class);
    public String                      tok;
    private String                     timeStamp;
    private String                     origIP;
    public final static String         TOKEN    = "tkn";
    private static final long          TIME_OUT = 30 * 60 * 1000; // miliseconds

    // shhhh ... this is my secred key!
    private static final byte[]        KEY      = "73edbe4f4c8d46ce".getBytes();
    private static final SecretKeySpec KEYSPEC  = new SecretKeySpec(KEY, "AES");

    /**
     * Add the token to the url and make sure it is properly encoded.
     *
     * @param url - a string representing the url
     * @return properly encoded url string.
     */
    public String toHttp(String url) {
        String u = url == null ? "" : url;
        if (u.indexOf("?") == -1) {
            u += "?";
        } else if (!u.endsWith("?") && !u.endsWith("&")) {
            u += "&";
        }
        logger.trace("Token before encoding:" + tok + " length=" + tok.length());
        String utok;
        try {
            utok = URLEncoder.encode(tok, "UTF8");
            logger.trace("Token after encoding:" + utok + " length=" + utok.length());
            u += TOKEN + "=" + utok;
        } catch (UnsupportedEncodingException e) {
            logger.info("", e);
        }
        return u;
    }

    /**
     * Use this method instead of getToken() if you need to pass the token via HTTP.
     *
     * @return a URL encoded token string.
     * */
    public String getUrlEncodedToken() {
        String token = this.tok;
        try {
            // encode the string to make sure no funny characters are passed in request
            token = URLEncoder.encode(this.tok, "UTF8");
        } catch (UnsupportedEncodingException e) {
            logger.info("Cannot encode token", e);
        }
        return token;
    }


    public static UserToken createUserToken(String userNm, String passwd, Http.Request req) {
        return createUserToken(userNm, passwd, getClientIP(req));
    }

    /**
     *
     * @param userNm
     * @param passwd
     * @return
     */
    public static UserToken createUserToken(String userNm, String passwd, String origIP) {
        if (userNm == null || passwd == null) {
            logger.info("Cannot create token");
            return null;
        }
        UserToken ut = new UserToken();
        try {
            ut.name = userNm;
            ut.password = passwd;
            ut.origIP = origIP;
            ut.timeStamp = String.valueOf(System.currentTimeMillis());
            ut.tok = encrypt(ut.timeStamp + "/" + userNm + "/" + passwd + "/" + origIP);
        } catch (Exception e) {
            logger.info("cannot create token", e);
            return null;
        }
        if (ut.tok == null) {
            logger.info("cannot encrypt token !");
            return null;
        }
        logger.trace("created UserToken: " + ut.tok + " length=" + ut.tok.length());
        return ut;
    }


    /**
     *
     * @param token
     * @param env
     * @return
     */
    public static UserToken createUserToken(String token, Http.Request req) {
        if (token == null) {
            logger.info("Cannot create token");
            return null;
        }
        UserToken ut = new UserToken();
        logger.trace("create UserToken from: " + token + " length=" + token.length());
        try {
            String decrypted = decrypt(token);
            if (decrypted == null) {
                logger.info("Cannot decrypt token.");
                return null;
            }
            int idx = decrypted.indexOf("/");
            String timeStr = decrypted.substring(0, idx++);
            ut.timeStamp = timeStr;
            long time = Long.parseLong(timeStr);
            long currTime = System.currentTimeMillis();

            long diff = currTime - time;
            if (diff > UserToken.TIME_OUT) {
                logger.info("token has expired for " + diff + " ms; timeout=" + UserToken.TIME_OUT + " ms.");
                return null;
            }
            int idx1 = decrypted.indexOf("/", idx);
            ut.name = decrypted.substring(idx, idx1++);
            int idx2 = decrypted.indexOf("/", idx1);
            ut.password = decrypted.substring(idx1, idx2++);
            ut.origIP = decrypted.substring(idx2);
            ut.tok = token;
            if (req != null) {
                // validate token IP
                String clientIP = getClientIP(req);
                if (!ut.origIP.equalsIgnoreCase(clientIP)) {
                    logger.info("Token orginated from different IP than request");
                    return null;
                }
            }
        } catch (Exception e) {
            logger.info("cannot create token", e);
            return null;
        }
        return ut;
    }

    private static String encrypt(String in) {
        try {
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, KEYSPEC);
            byte[] encrypted = cipher.doFinal(in.getBytes());
            return Base64.encode(encrypted);
        } catch (Exception e) {
            logger.info("failed encrypting string ...", e);
            return in;
        }
    }

    private static String decrypt(String in) {
        try {
            byte[] base64Decoded = Base64.decode(in);
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, KEYSPEC);
            byte[] plainText = cipher.doFinal(base64Decoded);
            return new String(plainText);
        } catch (Exception e) {
            logger.info("failed decrypting string ...", e);
            return in;
        }
    }

    /**
     * @param ctx
     * @return
     */
    private static String getClientIP(Http.Request req) {
        if (checkIP(req, "HTTP_CLIENT_IP")) {
            return req.getHeader("HTTP_CLIENT_IP");
        }
//        foreach (explode(",",$_SERVER["HTTP_X_FORWARDED_FOR"]) as $ip) {
//            if (checkIP(trim($ip))) return $ip;
//        }
        if (checkIP(req, "HTTP_X_FORWARDED")) {
            return req.getHeader("HTTP_X_FORWARDED");
        } else if (checkIP(req, "HTTP_X_CLUSTER_CLIENT_IP")) {
            return req.getHeader("HTTP_X_CLUSTER_CLIENT_IP");
        } else if (checkIP(req, "HTTP_FORWARDED_FOR")) {
            return req.getHeader("HTTP_FORWARDED_FOR");
        } else if (checkIP(req, "HTTP_FORWARDED")) {
            return req.getHeader("HTTP_FORWARDED");
        } else {
            return req.getHeader("REMOTE_ADDR");
        }
    }

    private static boolean checkIP(Http.Request req, String headerAttrNm) {
        String ip = req.getHeader(headerAttrNm);
        // TODO - additionally I could validate that this is in fact an IP
        if (ip != null && !ip.isEmpty()) {
            return true;
        }
        return false;
    }

//    private String asHex(byte buf[]) {
//        StringBuffer strbuf = new StringBuffer(buf.length * 2);
//        for (int i = 0; i < buf.length; i++) {
//            if ((buf[i] & 0xff) < 0x10)
//                strbuf.append("0");
//            strbuf.append(Long.toString(buf[i] & 0xff, 16));
//        }
//        return strbuf.toString();
//    }

    public static void main(String[] args) {
        UserToken ut = UserToken.createUserToken("aally", "parola", "127.0.0.1");
        System.out.println(ut.tok);
        UserToken ut1 = UserToken.createUserToken(ut.tok, null);
        System.out.println(ut1.name + " : " + ut.password + " : " + ut.origIP + " : " + ut.timeStamp + " => "
                + ut.tok.equals(ut.tok));
    }

}
