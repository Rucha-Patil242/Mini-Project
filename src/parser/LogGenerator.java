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
 * LogGenerator - creates a FAKE network log file for testing and demos.
 *
 * WHY THIS CLASS EXISTS
 *   We have no real network to monitor. So this class invents the traffic:
 *   mostly harmless events, plus several attackers of each kind hidden inside.
 *   Every other module (parser, detectors, alerts, graph, report) is tested on
 *   this file.
 *
 * HOW TO USE
 *   LogGenerator.generate("data/logs.txt", 1000);
 *
 * WHAT IT PRODUCES (with normalCount = 1000 and the default settings below)
 *   1000 normal events
 *   + 110 brute force events   10 attackers x 11 failed logins each
 *   + 120 port scan events     10 scanners  x 12 different ports each
 *   +  24 blacklisted events   6 blacklisted IPs x 4 events each
 *   = 1254 events, sorted by timestamp, one per line:
 *     timestamp, srcIp, dstIp, port, type, details
 *
 * Owner: A. Used by: LogParser, B's detectors, D's menu, and the 50K timing test.
 */
public class LogGenerator {

    // ---------- Settings: change these in ONE place only ----------

    // Ports used by normal traffic. Only 4 on purpose: a normal client can
    // never touch 10 different ports, so it can never trigger the port scan detector.
    private static final int[] NORMAL_PORTS = {80, 443, 22, 53};

    // First brute force and port scan attacker. More attackers count up from these
    // (203.0.113.9, .10, .11 ... and 198.51.100.7, .8, .9 ...).
    public static final String BRUTE_FORCE_IP = "203.0.113.9";
    public static final String PORT_SCAN_IP   = "198.51.100.7";

    // Every IP here must also be a line in data/blacklist.txt, written exactly the same.
    private static final String[] BLACKLISTED_IPS = {
            "45.33.32.156", "192.0.2.10", "192.0.2.25",
            "192.0.2.66", "198.51.100.99", "203.0.113.200"
    };

    // Kept so other classes that used the old single constant still compile.
    public static final String BLACKLISTED_IP = BLACKLISTED_IPS[0];

    // BruteForceDetector alerts when the count is MORE than 10 (count > 10),
    // so the alert fires on the 11th failure. 10 attempts is one short.
    private static final int BRUTE_FORCE_ATTEMPTS = 11;

    // How many different brute force attacker IPs to create.
    private static final int BRUTE_FORCE_ATTACKERS = 10;

    // How many different port scanner IPs to create.
    private static final int PORT_SCAN_ATTACKERS = 10;

    // How many events each blacklisted IP sends.
    private static final int BLACKLIST_EVENTS_PER_IP = 4;

    // The ports a scanner touches, one event each. PortScanDetector should fire
    // on the 10th distinct port (threshold = 10), so 12 gives a safe margin.
    private static final int[] SCAN_PORTS =
            {21, 22, 23, 25, 80, 110, 143, 443, 3306, 8080, 8443, 3389};

    /**
     * Writes a log file containing normal traffic plus injected attacks.
     *
     * @param file        path to write, e.g. "data/logs.txt"
     * @param normalCount how many harmless events to create (e.g. 1000)
     * @throws IOException if the file cannot be written (the menu catches this)
     */
    public static void generate(String file, int normalCount) throws IOException {

        // Fixed seed (42): the "random" numbers are the same on every run,
        // so everyone gets the same file and the same alerts. Good for demos/tests.
        Random rnd = new Random(42);

        // ArrayList holds every event in memory until we sort and write them.
        List<LogEvent> events = new ArrayList<>();

        // ---------- Step 1: normal traffic ----------
        // Harmless events: no LOGIN_FAILED, only 4 ports, so no detector fires.
        // Only this step uses rnd, so the normal traffic is identical on every run
        // no matter how the attack settings above are changed.
        long time = 1000;                                   // start time in ms
        for (int i = 0; i < normalCount; i++) {
            time += 1 + rnd.nextInt(20);                    // time moves forward 1..20 ms
            String src  = "192.168.1." + (1 + rnd.nextInt(50)); // 50 possible clients
            String dst  = "10.0.0."    + (1 + rnd.nextInt(4));  // 4 possible servers
            int port    = NORMAL_PORTS[rnd.nextInt(NORMAL_PORTS.length)];
            String type = rnd.nextBoolean() ? "CONNECT" : "LOGIN_OK";
            events.add(new LogEvent(time, src, dst, port, type, "none"));
        }

        // ---------- Step 2: attack 1 - brute force ----------
        // Each attacker makes BRUTE_FORCE_ATTEMPTS failed logins, 1 second apart,
        // all well inside the detector's 60 s window.
        // BruteForceDetector should fire on the 11th failure (count > 10).
        // The detector does not reset after alerting, so every attempt beyond
        // the 11th would raise another alert for the same IP.
        for (int a = 0; a < BRUTE_FORCE_ATTACKERS; a++) {
            // First attacker uses BRUTE_FORCE_IP, the others count up from its last number.
            String attackerIp = (a == 0) ? BRUTE_FORCE_IP : "203.0.113." + (9 + a);
            for (int i = 0; i < BRUTE_FORCE_ATTEMPTS; i++) {
                events.add(new LogEvent(2000 + i * 1000L, attackerIp, "10.0.0.5",
                        22, "LOGIN_FAILED", "user=admin"));
            }
        }

        // ---------- Step 3: attack 2 - port scan ----------
        // Each scanner sends CONNECTs to 12 DIFFERENT ports, 100 ms apart.
        // PortScanDetector should fire on the 10th distinct port (threshold = 10).
        for (int s = 0; s < PORT_SCAN_ATTACKERS; s++) {
            // First scanner uses PORT_SCAN_IP, the others count up from its last number.
            String scannerIp = (s == 0) ? PORT_SCAN_IP : "198.51.100." + (7 + s);
            for (int i = 0; i < SCAN_PORTS.length; i++) {
                events.add(new LogEvent(4000 + i * 100L, scannerIp, "10.0.0.2",
                        SCAN_PORTS[i], "CONNECT", "none"));
            }
        }

        // ---------- Step 4: attack 3 - blacklisted IPs ----------
        // Look like ordinary traffic, but each source IP is in data/blacklist.txt.
        // BlacklistDetector should fire on the very first event of every IP.
        for (String badIp : BLACKLISTED_IPS) {
            for (int i = 0; i < BLACKLIST_EVENTS_PER_IP; i++) {
                events.add(new LogEvent(6000 + i * 100L, badIp, "10.0.0.1",
                        80, "CONNECT", "none"));
            }
        }

        // ---------- Step 5: sort by time ----------
        // Attack events were added after the normal ones, so the list is out of
        // order. Detectors use sliding time windows and REQUIRE time order.
        // Comparator + sort is O(n log n).
        events.sort((a, b) -> Long.compare(a.getTimestamp(), b.getTimestamp()));

        // ---------- Step 6: write the file ----------
        File f = new File(file);
        if (f.getParentFile() != null) {
            f.getParentFile().mkdirs();                     // create data/ if missing (fresh clone)
        }
        // try-with-resources closes the file automatically, even if an error occurs.
        // BufferedWriter batches writes, which is much faster for 50,000 lines.
        try (BufferedWriter bw = new BufferedWriter(new FileWriter(f))) {
            for (LogEvent e : events) {
                bw.write(e.toString());                     // "timestamp, src, dst, port, type, details"
                bw.newLine();
            }
        }
    }
}