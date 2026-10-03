   package model;
//day 1
   public class LogEvent {
       private final long timestamp;
       private final String srcIp, dstIp, type, details;
       private final int port;

       public LogEvent(long timestamp, String srcIp, String dstIp,
                       int port, String type, String details) {
           this.timestamp = timestamp; this.srcIp = srcIp; this.dstIp = dstIp;
           this.port = port; this.type = type; this.details = details;
       }
       public long getTimestamp() { return timestamp; }
       public String getSrcIp()   { return srcIp; }
       public String getDstIp()   { return dstIp; }
       public int getPort()       { return port; }
       public String getType()    { return type; }
       public String getDetails() { return details; }

       @Override
       public String toString() {
           return timestamp + ", " + srcIp + ", " + dstIp + ", " + port + ", " + type + ", " + details;
       }
   }