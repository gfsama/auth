package util;

public class encryption {
    // restore user's password to an encrypted from
    public static String encrypt(String str){
        return str.hashCode()+"";
    } // hashcode as encryption
}
