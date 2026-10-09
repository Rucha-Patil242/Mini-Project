package detectors;

import model.Alert;
import model.LogEvent;
import model.Severity;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.HashSet;
import java.util.Set;

/**
 * BlacklistDetector - raises a CRITICAL alert when an event comes from an IP
 * that is listed in data/blacklist.txt.
 *
 * WHY A HashSet
 *   The only question we ask per event is "is this IP in the list?".
 *   HashSet answers that in O(1) on average, however long the list is.
 *   A List would need O(n) per event.
 *
 * HOW IT WORKS
 *   1. The constructor reads the file once and stores each IP in the set.
 *   2. analyze() checks the event's source IP against the set.
 *
 * NOTE: this detector has no memory of earlier events, so it returns an Alert
 * for EVERY event from a blacklisted IP. Duplicates are removed later by
 * AlertManager's cooldown and by ResponseEngine.block() (false if already blocked).
 *
 * Implements Detector's Interface
 */

public class BlacklistDetector implements Detector {
    private final Set<String> blacklist=new HashSet<>();

    public BlacklistDetector(String file){
        File f=new File(file);
        if(!f.exists()){
            System.out.println("Blacklist file not found: "+file+"(no IPs Blacklisted");
            return;
        }

        try(BufferedReader br=new BufferedReader(new FileReader(f))){
            String line;
            while((line=br.readLine())!=null){
                String ip=line.trim();
                if(!ip.isEmpty()){
                    blacklist.add(ip);
                }
            }
        }catch(IOException exception){
            System.out.println("Could not read"+ file+" : "+ exception.getMessage());
        }
    }
    /** Returns a CRITICAL Alert if the source IP is blacklisted, otherwise null. */

    @Override 
    public Alert analyze(LogEvent e){
        if(blacklist.contains(e.getSrcIp())){
            return new Alert(e.getSrcIp(), "BLACKLIST", Severity.CRITICAL, e.getTimestamp());
        }
        return null;
    }

    public int size(){
        return blacklist.size();
    }
    
}
