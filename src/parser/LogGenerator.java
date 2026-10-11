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
 *   mostly harmless events, plus three kinds of attackers hidden inside. Every
 *   other module (parser, detectors, alerts, graph, report) is tested on this file.
 *
 * HOW TO USE
 *   LogGenerator.generate("data/logs.txt", 1000);
 *
 * WHAT IT PRODUCES (with normalCount = 1000 and the default settings below)
 *   1000 normal events
 *   + 10 brute force events    from 203.0.113.9   (BRUTE_FORCE_ATTEMPTS x BRUTE_FORCE_ATTACKERS)
 *   + 12 port scan events      from 198.51.100.7
 *   +  4 blacklisted events    from 45.33.32.156
 *   = 1026 events, sorted by timestamp, one per line:
 *     timestamp, srcIp, dstIp, port, type, details
 *
 * Owner: A. Used by: LogParser, B's detectors, D's menu, and the 50K timing test.
 */
public class LogGenerator {

    // ---------- Settings: change these in ONE place only ----------

    // Ports used by normal traffic. Only 4 on purpose: a normal client can
    // never touch 10 different ports, so it can never trigger the port scan detector.
    private static final int[] NORMAL_PORTS = {80, 443, 22, 53};

    // The three attacker IPs. They are constants so the team can refer to them.
    // BLACKLISTED_IP must match the line in data/blacklist.txt exactly.
    public static final String BRUTE_FORCE_IP = "203.0.113.9";
    public static final String PORT_SCAN_IP   = "198.51.100.7";
    public static final String BLACKLISTED_IP = "45.33.32.156";

    // How many failed logins EACH brute force attacker makes.
    // Must be at least the detector's threshold (10) or no alert fires.
    private static final int BRUTE_FORCE_ATTEMPTS = 10;

    // How many different brute force attacker IPs to create.
    // 1 = just BRUTE_FORCE_IP. Set to 10 for ten attackers:
    // 203.0.113.9, 203.0.113.10, 203.0.113.11, ... (each last number goes up by 1).
    private static final int BRUTE_FORCE_ATTACKERS = 1;

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
        // BruteForceDetector should fire on the 10th failure (threshold = 10).
        // With exactly 10 attempts the alert fires on the last one. Use 12 to
        // also show the detector resetting after it alerts.
        for (int a = 0; a < BRUTE_FORCE_ATTACKERS; a++) {
            // First attacker uses BRUTE_FORCE_IP, the others count up from its last number.
            String attackerIp = (a == 0) ? BRUTE_FORCE_IP : "203.0.113." + (9 + a);
            for (int i = 0; i < BRUTE_FORCE_ATTEMPTS; i++) {
                events.add(new LogEvent(2000 + i * 1000L, attackerIp, "10.0.0.5",
                        22, "LOGIN_FAILED", "user=admin"));
            }
        }

        // ---------- Step 3: attack 2 - port scan ----------
        // 12 CONNECTs to 12 DIFFERENT ports, 100 ms apart.
        // PortScanDetector should fire on the 10th distinct port (threshold = 10).
        int[] scanPorts = {21, 22, 23, 25, 80, 110, 143, 443, 3306, 8080, 8443, 3389};
        for (int i = 0; i < scanPorts.length; i++) {
            events.add(new LogEvent(4000 + i * 100L, PORT_SCAN_IP, "10.0.0.2",
                    scanPorts[i], "CONNECT", "none"));
        }

        // ---------- Step 4: attack 3 - blacklisted IP ----------
        // Looks like ordinary traffic, but the source IP is in data/blacklist.txt.
        // BlacklistDetector should fire on the very first event.
        for (int i = 0; i < 4; i++) {
            events.add(new LogEvent(6000 + i * 100L, BLACKLISTED_IP, "10.0.0.1",
                    80, "CONNECT", "none"));
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