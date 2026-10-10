package core;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import model.Alert;

/**
 * Builds a summary of a run's alerts and writes it to a text file.
 *
 * The report has three parts: the total number of alerts, the alerts
 * counted by type, and the top attackers ranked by how many alerts each
 * IP caused.
 *
 * It only reads the alerts. It does not detect or block anything.
 */
public class ReportGenerator {

    private static final int TOP_N = 10;

    /**
     * Writes the report for every alert the AlertManager has accepted.
     * Uses getAllAlerts(), which is uncapped, so no alert is missing
     * (getHistory() only keeps the most recent ones).
     *
     * @param alertManager the manager that holds the run's alerts
     * @param filePath     where to write, for example "report.txt"
     * @throws IOException if the file cannot be written
     */
    public static void generate(AlertManager alertManager, String filePath) throws IOException {
        generate(alertManager.getAllAlerts(), filePath);
    }

    /**
     * Writes the report for the given alerts, creating the folder if
     * needed. Useful for tests that do not have an AlertManager.
     *
     * @param alerts   the alerts to summarize
     * @param filePath where to write, for example "report.txt"
     * @throws IOException if the file cannot be written
     */
    public static void generate(List<Alert> alerts, String filePath) throws IOException {
        if (alerts == null) {
            alerts = new ArrayList<>();
        }

        File out = new File(filePath);
        File parent = out.getParentFile();
        if (parent != null && !parent.exists()) {
            parent.mkdirs();
        }

        try (BufferedWriter bw = new BufferedWriter(new FileWriter(out))) {
            bw.write(buildReport(alerts));
        }
    }

    /**
     * Builds the report text without writing a file, so it can also be
     * printed in the menu or checked in a test.
     */
    public static String buildReport(List<Alert> alerts) {
        Map<String, Integer> byIp = new HashMap<>();
        Map<String, Integer> byType = new HashMap<>();

        for (Alert a : alerts) {
            byIp.merge(a.getip(), 1, Integer::sum);
            byType.merge(a.gettype(), 1, Integer::sum);
        }

        StringBuilder sb = new StringBuilder();
        sb.append("==== CyberShield Alert Report ====\n\n");
        sb.append("Total alerts: ").append(alerts.size()).append("\n\n");

        sb.append("-- Alerts by type --\n");
        if (byType.isEmpty()) {
            sb.append("(none)\n");
        } else {
            for (Map.Entry<String, Integer> e : sortedEntries(byType)) {
                sb.append(String.format("%-20s %d%n", e.getKey(), e.getValue()));
            }
        }

        sb.append("\n-- Top ").append(TOP_N).append(" attackers --\n");
        if (byIp.isEmpty()) {
            sb.append("(none)\n");
        } else {
            List<Map.Entry<String, Integer>> ranked = sortedEntries(byIp);
            int shown = Math.min(TOP_N, ranked.size());
            for (int i = 0; i < shown; i++) {
                Map.Entry<String, Integer> e = ranked.get(i);
                sb.append(String.format("%2d. %-18s %d alert(s)%n",
                        i + 1, e.getKey(), e.getValue()));
            }
        }

        return sb.toString();
    }

    /**
     * Sorts map entries by count, highest first. Ties are broken by key so
     * the same alerts always give the same report.
     */
    private static List<Map.Entry<String, Integer>> sortedEntries(Map<String, Integer> counts) {
        List<Map.Entry<String, Integer>> list = new ArrayList<>(counts.entrySet());
        list.sort((a, b) -> {
            int byCount = Integer.compare(b.getValue(), a.getValue());
            return byCount != 0 ? byCount : a.getKey().compareTo(b.getKey());
        });
        return list;
    }
}