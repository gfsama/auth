package entities;

public class token {
    private String username; // the user which the token bound to
    private boolean valid;   // token's status
    private Long refreshTime; // the latest refresh time

    public token(String username){
        this.username = username;
        reset();
    }

    public String getUsername(){
        return this.username;
    }

    public boolean getValid(){
        return this.valid;
    }

    public Long getRefreshTime(){
        return this.refreshTime;
    }

    public void reset(){
        this.valid = true;
        this.refreshTime = System.currentTimeMillis();
    }

    public void invalid(){
        this.valid = false;
    }
}
