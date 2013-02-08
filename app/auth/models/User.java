package auth.models;

import java.security.Principal;

import org.codehaus.jackson.JsonNode;
import org.codehaus.jackson.node.ObjectNode;

import play.libs.Json;

public class User implements Principal {

    public String name;
    public String password;
    public String fullName;

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