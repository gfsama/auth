package services;
import entities.*;
import java.util.*;
import static config.constants.*;
import static util.encryption.*;

public class auth {

    private HashMap<String,user> users = new HashMap<>(); // Users container
    private HashMap<String,role> roles = new HashMap<>(); // Roles container
    private HashMap<String,HashSet<String>> authorizationMap = new HashMap<>(); // Authorization mapper (user -> roles set)

    // Create User
    // Return（true: operation done; false: operation failed）
    public boolean createUser(String userName, String password){
        if(userExists(userName)) return false; // return false when user already exists
        users.put(userName,new user(userName,password)); // add user to container
        return true;
    }

    // Delete User
    // Return（true: operation done; false: operation failed）
    public boolean deleteUser(user u){
        if(u == null || !userExists(u.getName())) return false; // return false when user does not exist
        authorizationMap.remove(u.getName()); // remove from Authorization mapper
        users.remove(u.getName()); // remove from Users container
        return true;
    }

    // Create Role
    // Return（true: operation done; false: operation failed）
    public boolean createRole(String roleName){
        if(roleExists(roleName)) return false; // return false when role already exists
        roles.put(roleName,new role(roleName)); // add role to container
        return true;
    }

    // Delete Role
    // Return（true: operation done; false: operation failed）
    public boolean deleteRole(role r){
        if(r == null || !roleExists(r.getName())) return false; // return false when role does not exist
        // remove from Authorization mapper
        for(Map.Entry<String,HashSet<String>> entry : authorizationMap.entrySet()){
            if(entry.getValue().contains(r.getName())) entry.getValue().remove(r.getName());
        }
        roles.remove(r.getName()); // remove from Roles container
        return true;
    }

    // Add Role to User
    // Return（true: operation done; false: operation failed）
    public boolean addRoleToUser(role r, user u){
        if(u == null || !userExists(u.getName())) return false; // return false when user does not exist
        if(r == null || !roleExists(r.getName())) return false; // return false when role does not exist
        if(authorizationMap.containsKey(u.getName())){ // for existing user in Authorization mapper, upgrade its roles set
            authorizationMap.get(u.getName()).add(r.getName());
        }else{ // for users not exist in Authorization mapper, build up a new mapper (user -> roles set)
            HashSet<String> userRole = new HashSet<>();
            userRole.add(r.getName());
            authorizationMap.put(u.getName(),userRole);
        }
        return true;
    }

    // Authenticate User
    // Return（token: operation done; null: operation failed）
    public token authenticate(String userName, String password){
        if(userExists(userName) && users.get(userName).getPassword().equals(encrypt(password))){
            user u = users.get(userName);
            if(u.getToken() == null){ // if user does not hold a token, initiate a new token
                token t = new token(userName);
                u.setToken(t);
                return t;
            }else{ // if user does hold a token, refresh token
                u.getToken().reset();
                return u.getToken();
            }
        }else{
            return null; // user does not exist or password incorrect will return null
        }
    }

    // Invalidate token
    // Return（nothing）
    public void invalidate(token tkn){
        if(tkn != null) tkn.invalid();
    }

    // Check role
    // Return（1：matched; 0: unmatched; -1: error）
    public int checkRole(token tkn, role r){
        if(!tkn.getValid()) return -1; // return -1 when token invalidated
        if(tokenExpired(tkn)){ // return -1 when token expired, and upgrade token status
            tkn.invalid();
            return -1;
        }
        return authorizationMap.get(tkn.getUsername()).contains(r.getName()) ? 1 : 0;  // check if the token belongs to the role
    }

    // Show all roles for the user
    // Return（list of roles: operation done; null: error）
    public List<role> allRoles(token tkn){
        if(tkn == null || !tkn.getValid()) return null;
        List<role> ans = new ArrayList<>();
        for(String r : authorizationMap.get(tkn.getUsername())){
            ans.add(roles.get(r));
        }
        return ans; // return a list of role for the user
    }

    // judge if user exists in Users container
    private boolean userExists(String userName){
        return users.containsKey(userName);
    }

    // judge if role exists in Roles container
    private boolean roleExists(String roleName){
        return roles.containsKey(roleName);
    }

    // judge if token expired
    private boolean tokenExpired(token tkn){
        return System.currentTimeMillis() - tkn.getRefreshTime() > TOKEN_SPIRED_TIME;
    }

    //The following functions for test only
    public HashMap<String,user> getUsers(){
        return this.users;
    }

    public HashMap<String,role> getRoles(){
        return this.roles;
    }

    public HashMap<String,HashSet<String>> getAuthMap(){
        return this.authorizationMap;
    }
}
