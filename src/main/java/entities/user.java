package entities;
import util.encryption;

public class user {
    private String name;
    private String password;
    private token tkn; // the token belongs to the user (nullable)

    public user(String name, String password){
        this.name = name;
        this.password = new encryption().encrypt(password);
    }

    public String getName(){
        return this.name;
    }

    public String getPassword(){
        return this.password;
    }

    public token getToken(){
        return this.tkn;
    }

    public void setToken(token tkn) { this.tkn = tkn; }
}
