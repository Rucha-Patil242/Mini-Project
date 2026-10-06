package parser;

import model.LogEvent;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;

/**
 * LogParser - reads a log file and turns each line into a LogEvent object.
 *
 * WHY THIS CLASS EXISTS
 *   Detectors work with LogEvent objects, not raw text. The parser is the
 *   only place that reads text, so every other module can trust its input.
 *   It does not care whether the file came from LogGenerator or from elsewhere.
 *
 * HOW TO USE
 *   ArrayList<LogEvent> events = LogParser.parse("data/logs.txt");
 *
 * EXPECTED LINE FORMAT (6 fields, comma separated)
 *   timestamp, srcIp, dstIp, port, type, details
 *   1003, 192.168.1.14, 10.0.0.2, 443, CONNECT, none
 *
 * BAD INPUT IS SKIPPED, NOT FATAL
 *   Blank lines are ignored silently.
 *   Lines with the wrong number of fields, a non-numeric timestamp or port,
 *   or a port outside 0..65535 are counted as "skipped" and the parser moves on.
 *   A missing file returns an empty list instead of crashing.
 *
 * Owner: C (covering A while A is away). A takes this over on return.
 */
public class LogParser {

    private static final int FIELD_COUNT = 6;
    private static final int MIN_PORT = 0;
    private static final int MAX_PORT = 65535;

    /**
     * Reads the file and returns all valid events, in file order.
     *
     * @param file path to the log file, e.g. "data/logs.txt"
     * @return list of events; empty if the file is missing, empty or unreadable
     */
    public static ArrayList<LogEvent> parse(String file) {

        ArrayList<LogEvent> events = new ArrayList<>();   // O(1) append, keeps file order

        // ---------- Step 1: check the file exists ----------
        File f = new File(file);
        if (!f.exists()) {
            System.out.println("File not found: " + file);
            return events;                                 // empty list, no crash
        }

        int skipped = 0;                                   // count of bad lines

        // ---------- Step 2: read line by line ----------
        // try-with-resources closes the file automatically, even on error.
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            String line;
            while ((line = br.readLine()) != null) {       // null means end of file

                if (line.trim().isEmpty()) {
                    continue;                              // ignore blank lines
                }

                // Split into at most 6 parts. The limit means any extra commas
                // stay inside the last field (details) instead of breaking the line.
                String[] p = line.split(",", FIELD_COUNT);
                if (p.length != FIELD_COUNT) {
                    skipped++;                             // too few fields
                    continue;
                }

                // ---------- Step 3: convert text to numbers, validate ----------
                try {
                    long timestamp = Long.parseLong(p[0].trim());
                    int port = Integer.parseInt(p[3].trim());

                    if (port < MIN_PORT || port > MAX_PORT) {
                        skipped++;                         // impossible port number
                        continue;
                    }

                    // trim() removes the space after each comma in the file
                    events.add(new LogEvent(
                            timestamp,
                            p[1].trim(),                   // srcIp
                            p[2].trim(),                   // dstIp
                            port,
                            p[4].trim(),                   // type
                            p[5].trim()));                 // details
                } catch (NumberFormatException ex) {
                    skipped++;                             // timestamp or port was not a number
                }
            }
        } catch (IOException ex) {
            System.out.println("Could not read " + file + ": " + ex.getMessage());
        }

        // ---------- Step 4: report ----------
        System.out.println("Parsed " + events.size() + " events, skipped " + skipped);
        return events;
    }
}