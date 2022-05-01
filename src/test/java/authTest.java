import static config.constants.*;
import services.auth;
import entities.*;
import java.util.*;

public class authTest {

    public static final int SPACE = 25;
    public static final String SPLIT_LINE = "------------------------------------------------------------------------------";

    public static void main(String[] args){

        auth au = new auth();

        testCreateUser(au, "001", "pass1");
        testCreateUser(au, "002", "pass2");
        testCreateUser(au, "003", "pass3");
        testDeleteUser(au, "003");
        testDeleteUser(au, "004");
        describeUsers(au); // Show users information after user-concerned operations

        testCreateRole(au, "A");
        testCreateRole(au, "B");
        testCreateRole(au, "C");
        testDeleteRole(au, "C");
        testDeleteRole(au, "D");
        testCreateRole(au, "E");
        describeRoles(au); // Show roles information after role-concerned operations

        testAddRoleToUser(au, "001","A");
        testAddRoleToUser(au, "001","B");
        testAddRoleToUser(au, "002","B");
        testAddRoleToUser(au, "002","E");
        describeAuths(au); // Show authorization information after authorization-concerned operations

        testAuthenticate(au,"004","pass4");
        testAuthenticate(au,"001","pass1");
        testAuthenticate(au,"002","pass1");
        testAuthenticate(au,"002","pass2");
        describeAuthenticatedUsers(au); // Show authentication information after authentication-concerned operations

        testInvalidate(au,"003");
        testInvalidate(au,"002");
        describeAuthenticatedUsers(au); // Show authentication information after authentication-concerned operations

        // Check mapping between users and roles
        testCheckRole(au,"004","A");
        testCheckRole(au,"001","A");
        testCheckRole(au,"001","E");
        testCheckRole(au,"002","E");

        // Show roles for users
        testAllRoles(au,"004");
        testAllRoles(au,"002");
        testAllRoles(au,"001");

        executeSleep(TOKEN_SPIRED_TIME-1000);
        testCheckRole(au,"001","A");
        describeAuthenticatedUsers(au); // the authenticated user remains active before token time over

        testAuthenticate(au,"001","pass1"); // refresh to start over a new cycle
        executeSleep(TOKEN_SPIRED_TIME);
        testCheckRole(au,"001","A"); // check and upgrade token status (supposed to be a scheduled task)
        describeAuthenticatedUsers(au); // the authenticated user inactivated after token time over
    }

    //Test Functions
    public static void testCreateUser(auth au, String userName, String password){
        System.out.println("> CreateUser( username : " + userName + " , password : " + password + " )\n");
        au.createUser(userName,password);
    }

    public static void testDeleteUser(auth au, String userName){
        System.out.println("< DeleteUser( username : " + userName + " )\n");
        au.deleteUser(au.getUsers().get(userName));
    }

    public static void testCreateRole(auth au, String roleName){
        System.out.println("> CreateRole( rolename : " + roleName + " )\n");
        au.createRole(roleName);
    }

    public static void testDeleteRole(auth au, String roleName){
        System.out.println("< DeleteRole( rolename : " + roleName + " )\n");
        au.deleteRole(au.getRoles().get(roleName));
    }

    public static void testAddRoleToUser(auth au, String userName, String roleName){
        System.out.println("> AddRoleToUser( rolename : " + roleName + " , username : " + userName +" )\n");
        au.addRoleToUser(au.getRoles().get(roleName),au.getUsers().get(userName));
    }

    public static void testAuthenticate(auth au, String userName, String password){
        System.out.println("> AuthenticateUser( username : " + userName + " , password : " + password + " )");
        token tkn = au.authenticate(userName,password);
        if(tkn == null) System.out.println("Authentication Failed.");
        else System.out.println("Authentication Succeed.");
        System.out.println("");
    }

    public static void testInvalidate(auth au, String userName){
        System.out.println("< InvalidateUser( username : " + userName + " )\n");
        if(!au.getUsers().isEmpty() && au.getUsers().containsKey(userName)){
            au.invalidate(au.getUsers().get(userName).getToken());
        }
    }

    public static void testCheckRole(auth au, String userName, String roleName){
        System.out.println("> CheckRole( username : " + userName + " , rolename : " + roleName +" )");
        if(!au.getUsers().isEmpty() && au.getUsers().containsKey(userName) &&
                !au.getRoles().isEmpty() && au.getRoles().containsKey(roleName) &&
                !au.getAuthMap().isEmpty() && au.getAuthMap().containsKey(userName)){
            int res = au.checkRole(au.getUsers().get(userName).getToken(),au.getRoles().get(roleName));
            if(res == 1) System.out.println("Matched.\n");
            else if(res == 0) System.out.println("Unmatched.\n");
            else if(res == -1) System.out.println("Error, invalid token.\n");
        }else System.out.println("Error, no such user or role.\n");
    }

    public static void testAllRoles(auth au, String userName){
        System.out.println("> AllRoles( username : " + userName +" )");
        if(!au.getUsers().isEmpty() && au.getUsers().containsKey(userName) &&
                !au.getAuthMap().isEmpty() && au.getAuthMap().containsKey(userName)){
            List<role> roleList = au.allRoles(au.getUsers().get(userName).getToken());
            if(roleList == null){
                System.out.println("Error, invalid token.\n");
            }else{
                if(roleList.isEmpty()) System.out.println("Empty roles.\n");
                else{
                    System.out.println("#" + reform("RoleName"));
                    System.out.println(SPLIT_LINE);
                    int cnt = 1;
                    for(role r : roleList){
                        System.out.println(cnt++ + "" + reform(r.getName()));
                    }
                    System.out.println("");
                }
            }
        }else System.out.println("Error, no such user.\n");
    }

    //Show the information stored in memory
    public static void describeUsers(auth au){
        System.out.println("[USERS]");
        if(au.getUsers().isEmpty()){
            System.out.println("(Empty)");
            return;
        }
        System.out.println("#" + reform("UserName") + reform("Encrypted Password"));
        System.out.println(SPLIT_LINE);
        int cnt = 1;
        for(Map.Entry<String,user> entry : au.getUsers().entrySet()){
            System.out.println(cnt++ + "" + reform(entry.getValue().getName()) + reform(entry.getValue().getPassword()));
        }
        System.out.println("");
    }

    public static void describeRoles(auth au){
        System.out.println("[ROLES]");
        if(au.getRoles().isEmpty()){
            System.out.println("(Empty)");
            return;
        }
        System.out.println("#" + reform("RoleName"));
        System.out.println(SPLIT_LINE);
        int cnt = 1;
        for(Map.Entry<String,role> entry : au.getRoles().entrySet()){
            System.out.println(cnt++ + "" + reform(entry.getValue().getName()));
        }
        System.out.println("");
    }

    public static void describeAuths(auth au){
        System.out.println("[Authentications]");
        if(au.getAuthMap().isEmpty()){
            System.out.println("(Empty)");
            return;
        }
        System.out.println("#" + reform("UserName") + reform("Roles"));
        System.out.println(SPLIT_LINE);
        int cnt = 1;
        for(Map.Entry<String,HashSet<String>> entry : au.getAuthMap().entrySet()){
            StringBuffer sb = new StringBuffer();
            for(String rolename : entry.getValue()){
                sb.append(rolename + ",");
            }
            if(sb.length() > 0) sb.deleteCharAt(sb.length()-1);
            System.out.println(cnt++ + "" + reform(entry.getKey()) + reform(sb.toString()));
        }
        System.out.println("");
    }

    public static void describeAuthenticatedUsers(auth au){
        System.out.println("[Authenticated USERS]");
        if(au.getUsers().isEmpty()){
            System.out.println("(Empty)");
            return;
        }
        System.out.println("#" + reform("UserName") + reform("Token Refreshed Time"));
        System.out.println(SPLIT_LINE);
        int cnt = 1;
        for(Map.Entry<String,user> entry : au.getUsers().entrySet()){
            if(entry.getValue().getToken() != null && entry.getValue().getToken().getValid()) {
                System.out.println(cnt++ + ""
                        + reform(entry.getValue().getName()) + reform(entry.getValue().getToken().getRefreshTime() + ""));
            }
        }
        System.out.println("");
    }

    public static String reform(String str){
        return String.format("%1$"+SPACE+"s",str);
    }

    public static void executeSleep(long time){
        try{
            Thread.sleep(time);
            System.out.println("> Sleep for " + time + " millis.\n");
        }catch(InterruptedException e){}
    };
}
