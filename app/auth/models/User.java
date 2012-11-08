//==========================================================================
// $Id: User.java,v 1.1.2.1 2012/06/20 18:38:08 cristiand Exp $
// (@) Copyright Sigma Systems (Canada)
// * Based on CVS log
//==========================================================================
package auth.models;

import java.security.Principal;

import javax.persistence.Entity;
import javax.persistence.Id;

import org.codehaus.jackson.JsonNode;
import org.codehaus.jackson.node.ObjectNode;

import play.data.validation.Constraints;
import play.db.ebean.Model;
import play.libs.Json;

@SuppressWarnings("serial")
@Entity
public class User extends Model implements Principal {

    @Id
    @Constraints.Required
    public String name;

    @Constraints.Required
    public String password;

    public String fullName;

    // key class, bean class
    public static final Finder<String,User> find = new Finder<String,User>(String.class, User.class);

    public static User find(String username, String password) {
        return User.find.where().eq("name", username).eq("password", password).findUnique();
    }

    public String toJson() {
        ObjectNode on = Json.newObject();
        on.put("name", name);
        on.put("fullName", fullName);
        return Json.stringify(on);
    }

    public static User fromJson(String json) {
        User user = Json.fromJson(Json.parse(json), User.class);
        return user;
    }

    public static void main(String[] args) {
        User u = new User();
        u.name = "johndoe";
        u.fullName = "John Doe";
        String json = u.toJson();
        System.out.println("JSON: " + json);
        u = User.fromJson(json);
        System.out.println("User: " + u.toJson());
        JsonNode n = Json.toJson(u);
        json = Json.stringify(n);
        System.out.println("json: " + json);
        u = User.fromJson(json);
        System.out.println("User: " + u.toJson());
    }

    /* (non-Javadoc)
     * @see java.security.Principal#getName()
     */
    @Override
    public String getName() {
        return name;
    }
}