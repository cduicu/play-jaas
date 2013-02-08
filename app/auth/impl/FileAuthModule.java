package auth.impl;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.util.HashMap;
import java.util.Map;
import java.util.StringTokenizer;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.LoginException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import play.mvc.Http.Request;
import auth.models.User;
import auth.models.UserToken;
import auth.utils.AuthUtils;

public class FileAuthModule extends BasicUserPwdAuthModule {

    private static Logger                logger           = LoggerFactory.getLogger(FileAuthModule.class);
    private static final String          FILE_AUTH_MODULE = "FileAuth";
    private String                       pwdFile;
    private long                         lastModified     = 0;
    private static HashMap<String, User> users;

    /**
     *
     * @param f
     * @throws Exception
     */
    private void load(File f) throws Exception {
        lastModified = f.lastModified();
        BufferedReader r = new BufferedReader(new FileReader(f));
        users = new HashMap<String, User>();
        String l = r.readLine();
        while (l != null) {
            int hash = l.indexOf('#');
            if (hash != -1) {
                l = l.substring(0, hash);
            }
            l = l.trim();
            if (l.length() != 0) {
                StringTokenizer t = new StringTokenizer(l, ":");
                User u = new User();
                u.name = t.nextToken();
                u.password = t.nextToken();
                u.fullName = t.nextToken();
                users.put(u.name, u);
            }
            l = r.readLine();
        }
        r.close();
        logger.debug("loaded password file: " + users.size() + " users");
    }

    private void reload() throws Exception {
        File f = new File(pwdFile);
        if (users == null || f.lastModified() != lastModified) {
            logger.debug("loading file " + f.toURI());
            load(f);
        }
    }

    @Override
    public void initialize(Subject subject, CallbackHandler callbackHandler, Map<String, ?> sharedState,
            Map<String, ?> options) {
        super.initialize(subject, callbackHandler, sharedState, options);
        pwdFile = getOption("pwdFile", null);
        if (pwdFile == null) {
            throw new RuntimeException("Must configure password file in JAAS (pwdFile=?)");
        }
    }

    /*
     * (non-Javadoc)
     *
     * @see auth.IAuthModule#getModuleName()
     */
    @Override
    public String getModuleName() {
        return FILE_AUTH_MODULE;
    }

    /*
     * (non-Javadoc)
     *
     * @see auth.impl.BasicUserPwdAuthModule#validateCredentials(java.lang.String, java.lang.String,
     * play.mvc.Http.Request)
     */
    @Override
    protected User validateCredentials(String username, String password, Request req) throws LoginException {
        logger.debug("validateCredentials()");
        try {
            reload();
        } catch (Exception e) {
            throw new LoginException("Error reading " + pwdFile + " (" + e.getMessage() + ")");
        }
        if (users == null || !users.containsKey(username)) {
            logger.trace("user " + username + " not found");
            return null;
        }
        User u = users.get(username);
        String pwd = AuthUtils.encrypt(password);
        if (u.password.equals(pwd)) {
            User user = UserToken.createUserToken(username, password, req);
            user.fullName = u.fullName;
            return user;
        }
        return null;
    }

}
