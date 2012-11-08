//==========================================================================
// $Id: DBAuthModule.java,v 0.1 Oct 30, 2012 11:30:35 PM cristiand Exp $
// (@) Copyright Sigma Systems (Canada)
// * Based on CVS log
//==========================================================================
package auth.impl;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.Map;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.LoginException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import play.mvc.Http.Request;
import auth.models.User;
import auth.models.UserToken;
import auth.utils.AuthUtils;

/**
 * @version $Revision: $
 * @author $Author: cristiand $
 * @since $Date: Oct 30, 2012 $
 */
public class JDBCAuthModule extends BasicUserPwdAuthModule {

    private static Logger       logger         = LoggerFactory.getLogger(JDBCAuthModule.class);
    private static final String DB_AUTH_MODULE = "JDBCAuth";
    protected String            dbDriver;
    protected String            dbURL;
    protected String            dbUser;
    protected String            dbPassword;
    protected String            userTable;
//    protected String            roleMapTable;
//    protected String            roleTable;
    protected String            where;

    /*
     * (non-Javadoc)
     *
     * @see auth.IAuthModule#getModuleName()
     */
    @Override
    public String getModuleName() {
        return DB_AUTH_MODULE;
    }

    @Override
    public void initialize(Subject subject, CallbackHandler callbackHandler, Map<String, ?> sharedState,
            Map<String, ?> options) {
        super.initialize(subject, callbackHandler, sharedState, options);

        dbDriver = getOption("dbDriver", null);
        if (dbDriver == null) {
            throw new RuntimeException("No database driver named (dbDriver=?)");
        }
        dbURL = getOption("dbURL", null);
        if (dbURL == null)
            throw new RuntimeException("No database URL specified (dbURL=?)");
        dbUser = getOption("dbUser", null);
        dbPassword = getOption("dbPassword", null);
        if ((dbUser == null && dbPassword != null) || (dbUser != null && dbPassword == null)) {
            throw new RuntimeException("Either provide dbUser and dbPassword or encode both in dbURL");
        }
        userTable = getOption("userTable", "Users");
        where = getOption("where", "");
        if (null != where && where.length() > 0) {
            where = " AND " + where;
        } else {
            where = "";
        }
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
        ResultSet rsu = null, rsr = null;
        Connection con = null;
        PreparedStatement psu = null, psr = null;
        try {
            Class.forName(dbDriver);
            if (dbUser != null) {
                con = DriverManager.getConnection(dbURL, dbUser, dbPassword);
            } else {
                con = DriverManager.getConnection(dbURL);
            }
            psu = con.prepareStatement("SELECT password,fullname FROM " + userTable + " WHERE userid=?" + where);
            psu.setString(1, username);
            rsu = psu.executeQuery();
            if (!rsu.next()) {
                return null;
            }
            String dbpassword = rsu.getString(1);
            String fullname = rsu.getString(2);
            String pwd = AuthUtils.encrypt(password);
            if (dbpassword.equals(pwd)) {
                User user = UserToken.createUserToken(username, password, req);
                user.fullName = fullname;
                return user;
            }
        } catch (Exception e) {
            throw new LoginException("Error reading user database (" + e.getMessage() + ")");
        } finally {
            try {
                if (rsu != null) rsu.close();
                if (rsr != null) rsr.close();
                if (psu != null) psu.close();
                if (psr != null) psr.close();
                if (con != null) con.close();
            } catch (Exception e) { }
        }
        return null;
    }

}
