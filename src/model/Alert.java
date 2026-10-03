package model;

public class Alert {
    private String ip;
    private String type;
    private Severity severity ;
    private long timestamp;
    Alert(String ip, String type,Severity severity,long timestamp){
        this.ip=ip;
        this.type=type;
        this.severity=severity;
        this.timestamp=timestamp;
    }
    public String getip() {
    return ip;
}
public String gettype() {
    return type;
}
public Severity getseverity() {
    return severity;
}
public Long gettimestamp(){
    return timestamp;
}
@Override
public String toString() {
    return "[" + severity + "] " + type + " from " + ip + " at t=" + timestamp;
}
}
