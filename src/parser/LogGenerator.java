package parser;

import model.LogEvent;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

/**
 * Creates a fake network log file: normal traffic plus planted attacks, so the
 * expected alerts are known. Each line is: timestamp, srcIp, dstIp, port, type, details.
 *
 * With normalCount = 1000 and the defaults below: 1000 + 110 brute force
 * + 120 port scan + 24 blacklisted = 1254 events, sorted by timestamp.
 */
public class LogGenerator {

    // Only 4 ports, so normal clients can never look like a port scan.
    private static final int[] NORMAL_PORTS = {80, 443, 22, 53};

    // First brute force and port scan attacker; the rest count up from these.
    public static final String BRUTE_FORCE_IP = "203.0.113.9";
    public static final String PORT_SCAN_IP   = "198.51.100.7";

    // Must match the lines in data/blacklist.txt exactly.
    private static final String[] BLACKLISTED_IPS = {
            "45.33.32.156", "192.0.2.10", "192.0.2.25",
            "192.0.2.66", "198.51.100.99", "203.0.113.200"
    };
    public static final String BLACKLISTED_IP = BLACKLISTED_IPS[0];

    // The detector alerts when count > 10, so the 11th failure triggers it.
    private static final int BRUTE_FORCE_ATTEMPTS = 11;
    private static final int BRUTE_FORCE_ATTACKERS = 10;
    private static final int PORT_SCAN_ATTACKERS = 10;
    private static final int BLACKLIST_EVENTS_PER_IP = 4;

    // 12 distinct ports; the detector fires at 10.
    private static final int[] SCAN_PORTS =
            {21, 22, 23, 25, 80, 110, 143, 443, 3306, 8080, 8443, 3389};

    /**
     * @param file        path to write, e.g. "data/logs.txt"
     * @param normalCount how many harmless events to create
     * @throws IOException if the file cannot be written
     */
    public static void generate(String file, int normalCount) throws IOException {

        // Fixed seed: same data on every run.
        Random rnd = new Random(42);
        List<LogEvent> events = new ArrayList<>();

        // Normal traffic (the only step that uses rnd).
        long time = 1000;
        for (int i = 0; i < normalCount; i++) {
            time += 1 + rnd.nextInt(20);
            String src  = "192.168.1." + (1 + rnd.nextInt(50));
            String dst  = "10.0.0."    + (1 + rnd.nextInt(4));
            int port    = NORMAL_PORTS[rnd.nextInt(NORMAL_PORTS.length)];
            String type = rnd.nextBoolean() ? "CONNECT" : "LOGIN_OK";
            events.add(new LogEvent(time, src, dst, port, type, "none"));
        }

        // Brute force: failed logins 1 second apart, inside the 60 s window.
        for (int a = 0; a < BRUTE_FORCE_ATTACKERS; a++) {
            String attackerIp = (a == 0) ? BRUTE_FORCE_IP : "203.0.113." + (9 + a);
            for (int i = 0; i < BRUTE_FORCE_ATTEMPTS; i++) {
                events.add(new LogEvent(2000 + i * 1000L, attackerIp, "10.0.0.5",
                        22, "LOGIN_FAILED", "user=admin"));
            }
        }

        // Port scan: one CONNECT per port, 100 ms apart.
        for (int s = 0; s < PORT_SCAN_ATTACKERS; s++) {
            String scannerIp = (s == 0) ? PORT_SCAN_IP : "198.51.100." + (7 + s);
            for (int i = 0; i < SCAN_PORTS.length; i++) {
                events.add(new LogEvent(4000 + i * 100L, scannerIp, "10.0.0.2",
                        SCAN_PORTS[i], "CONNECT", "none"));
            }
        }

        // Blacklisted IPs: ordinary-looking traffic from listed sources.
        for (String badIp : BLACKLISTED_IPS) {
            for (int i = 0; i < BLACKLIST_EVENTS_PER_IP; i++) {
                events.add(new LogEvent(6000 + i * 100L, badIp, "10.0.0.1",
                        80, "CONNECT", "none"));
            }
        }

        // Detectors need time order; attacks were added out of order.
        events.sort((a, b) -> Long.compare(a.getTimestamp(), b.getTimestamp()));

        File f = new File(file);
        if (f.getParentFile() != null) {
            f.getParentFile().mkdirs();
        }
        try (BufferedWriter bw = new BufferedWriter(new FileWriter(f))) {
            for (LogEvent e : events) {
                bw.write(e.toString());
                bw.newLine();
            }
        }
    }
}