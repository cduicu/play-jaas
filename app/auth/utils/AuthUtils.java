//==========================================================================
// $Id: AuthUtils.java,v 0.1 Oct 30, 2012 10:56:29 PM cristiand Exp $
// (@) Copyright Sigma Systems (Canada)
// * Based on CVS log
//==========================================================================
package auth.utils;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;

import play.Logger;

/**
 * @version $Revision: $
 * @author $Author: cristiand $
 * @since $Date: Oct 30, 2012 $
 */
public class AuthUtils {

    private final static String  ALGORITHM = "SHA-256";
    private static MessageDigest md        = null;

    /**
     * Turn a byte array into a char array containing a printable hex representation of the bytes.
     * Each byte in the source array contributes a pair of hex digits to the output array.
     *
     * @param src the source array
     * @return a char array containing a printable version of the source data
     */
    private static char[] hexDump(byte src[]) {
        char buf[] = new char[src.length * 2];
        for (int b = 0; b < src.length; b++) {
            String byt = Integer.toHexString(src[b] & 0xFF);
            if (byt.length() < 2) {
                buf[b * 2 + 0] = '0';
                buf[b * 2 + 1] = byt.charAt(0);
            } else {
                buf[b * 2 + 0] = byt.charAt(0);
                buf[b * 2 + 1] = byt.charAt(1);
            }
        }
        return buf;
    }

    /**
     * Zero the contents of the specified array.
     *
     * @param pwd the array to zero
     */
    private static void smudge(byte pwd[]) {
        if (null != pwd) {
            for (int b = 0; b < pwd.length; b++) {
                pwd[b] = 0;
            }
        }
    }

    /**
     * Perform MD5 hashing on the supplied password and return a char array containing the encrypted
     * password as a printable string. The hash is computed on the low 8 bits of each character.
     *
     * @param password
     * @return
     */
    public static String encrypt(String password) {
        char pwd[] = password.toCharArray();
        if (md == null) {
            try {
                md = MessageDigest.getInstance(ALGORITHM);
            } catch (NoSuchAlgorithmException e) {
                Logger.info("Failed encrypting password!", e);
            }
        }
        md.reset();
        byte pwdb[] = new byte[pwd.length];
        for (int b = 0; b < pwd.length; b++) {
            pwdb[b] = (byte) pwd[b];
        }
        char crypt[] = hexDump(md.digest(pwdb));
        smudge(pwdb);
        return new String(crypt);
    }

    public static void main(String[] args) {
        HashMap<String, String> users = new HashMap<String, String>();
        users.put("test", "John Doe");
        users.put("aalli", "Ally Alligator");
        users.put("bbear", "Billy Bear");
        users.put("ccat", "Carrie Cat");
        users.put("dduck", "David Duck");
        users.put("eeagle", "Eva Eagle");
        for (String nm : users.keySet()) {
            System.out.println(nm + ":" + encrypt("pw" + nm) + ":" + users.get(nm));
        }
    }

}
