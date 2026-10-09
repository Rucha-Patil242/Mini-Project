package core;

import model.Alert;
import model.Severity;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.PriorityQueue;

/**
 * Receives alerts from the detectors.
 * - PriorityQueue: pending alerts, most severe first (ties: oldest first).
 * - LinkedList:    capped history of recent alerts (O(1) add/remove at the ends).
 * - HashMap:       last alert time per (type, ip), used for cooldown.
 * - ArrayList:     full list of every accepted alert, used by the report.
 */
public class AlertManager {

    private static final Comparator<Alert> SEVERITY_THEN_TIME = (a, b) -> {
        int bySeverity = b.getseverity().compareTo(a.getseverity()); // CRITICAL first
        if (bySeverity != 0) return bySeverity;
        return Long.compare(a.gettimestamp(), b.gettimestamp());
    };

    private final PriorityQueue<Alert> pending = new PriorityQueue<>(SEVERITY_THEN_TIME);
    private final LinkedList<Alert> history = new LinkedList<>();
    private final List<Alert> allAlerts = new ArrayList<>();
    private final Map<String, Long> lastSeen = new HashMap<>();

    /**
     * Accepts an alert unless the same type from the same IP fired within the cooldown.
     * @return true if the alert was accepted, false if it was suppressed or null.
     */
    public boolean raise(Alert alert) {
        if (alert == null) return false;

        String key = alert.gettype() + "|" + alert.getip();
        Long last = lastSeen.get(key);
        if (last != null && alert.gettimestamp() - last < Config.ALERT_COOLDOWN) {
            return false;
        }
        lastSeen.put(key, alert.gettimestamp());

        pending.add(alert);
        allAlerts.add(alert);
        history.addLast(alert);
        if (history.size() > Config.MAX_HISTORY) {
            history.removeFirst();
        }
        return true;
    }

    /** Removes and returns the most severe pending alert, or null if none. */
    public Alert nextAlert() {
        return pending.poll();
    }

    public boolean hasPendingAlerts() {
        return !pending.isEmpty();
    }

    public int pendingCount() {
        return pending.size();
    }

    /** Last MAX_HISTORY accepted alerts, oldest first. Read-only. */
    public List<Alert> getHistory() {
        return Collections.unmodifiableList(history);
    }

    /** Every accepted alert, uncapped. Use this for the report. Read-only. */
    public List<Alert> getAllAlerts() {
        return Collections.unmodifiableList(allAlerts);
    }
}