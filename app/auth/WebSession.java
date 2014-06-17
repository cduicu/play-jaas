package auth;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import play.cache.Cache;
import play.mvc.Http;

import java.io.Serializable;
import java.util.HashMap;

/**
 * Simulates the Servlet's HTTPSession object.
 */
public class WebSession {

    private static Logger logger = LoggerFactory.getLogger(WebSession.class);
    private long lastAccessTime;
    private String id;
    public static long TIME_OUT = 20 * 60000; // 20 min.
    private HashMap<String,Serializable> sessionData = new HashMap<String,Serializable>();

    private WebSession(String id) {
        this.id = id;
        this.lastAccessTime = System.currentTimeMillis();
    }

    public static WebSession newSession(Http.Session session) {
        String id = java.util.UUID.randomUUID().toString();
        logger.info("New session created id=" + id);
        session.put("uuid", id);
        WebSession s = new WebSession(id);
        Cache.set(id, s);
        return s;
    }

    public static WebSession getSession(Http.Session session) {
        return getSession(session, false);
    }

    public static WebSession getSession(Http.Session session, boolean autoCreate) {
        WebSession s = null;
        if (session == null) {
            logger.info("Session is null!");
            return null;
        }
        String id = session.get("uuid");
        if (id == null) {
            if (!autoCreate) {
                return null;
            } else {
                s = WebSession.newSession(session);
            }
        } else {
            s = (WebSession) Cache.get(id);
            if (s == null) {
                logger.error("Cannot get session with id=" + id + " from cache!");
            }
        }
        if (s != null) {
            if (s.lastAccessTime < System.currentTimeMillis() - TIME_OUT) {
                // session expired
                logger.info("Session expired! id=" + id);
                removeSession(id);
                s = null;
            }
        }
        if (s!= null) {
            s.touch();
        }
        return s;
    }

    public static Object get(Http.Session session, String key) {
        WebSession s = getSession(session);
        if (s != null) {
            return s.get(key);
        }
        return null;
    }

    public static void removeSession(String id) {
        if (id != null) {
            logger.info("Removing session id=" + id);
            Cache.set(id, null);
        }
    }

    public Object get(String key) {
        touch();
        return sessionData.get(key);
    }

    private void touch() {
        lastAccessTime = System.currentTimeMillis();
    }

    public String getId() {
        return id;
    }

    public void put(String key, Object value) {
        touch();
        sessionData.put(key, (Serializable) value);
    }



}
