package core;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * In-memory list of IP addresses that the system has blocked.
 *
 * IPs get here in two ways: ResponseEngine blocks an IP automatically when a
 * HIGH or CRITICAL alert fires, or the analyst blocks one from the menu.
 * Unlike data/blacklist.txt (known-bad IPs loaded before the run), this list
 * is built during the run and is lost when the program closes.
 *
 * A LinkedHashSet is used because:
 *  - contains/add/remove are O(1) on average, so isBlocked() is fast even
 *    when it is checked for every event
 *  - duplicates are ignored automatically, so blocking an IP twice is safe
 *  - it remembers insertion order, so the menu can show IPs in the order
 *    they were blocked
 */
public class BlockList {

    private final Set<String> blocked = new LinkedHashSet<>();

    /**
     * Blocks an IP.
     *
     * @return true if the IP was newly blocked, false if it was already
     *         blocked or the input was null/blank
     */
    public boolean block(String ip) {
        if (ip == null) {
            return false;
        }
        String clean = ip.trim();
        if (clean.isEmpty()) {
            return false;
        }
        return blocked.add(clean);
    }

    /**
     * Removes an IP from the list (analyst override for a false positive).
     *
     * @return true if the IP was blocked and is now removed
     */
    public boolean unblock(String ip) {
        if (ip == null) {
            return false;
        }
        return blocked.remove(ip.trim());
    }

    /** @return true if this IP is currently blocked */
    public boolean isBlocked(String ip) {
        if (ip == null) {
            return false;
        }
        return blocked.contains(ip.trim());
    }

    /**
     * @return a read-only copy of all blocked IPs in the order they were
     *         blocked. A copy is returned so callers cannot change the
     *         list without going through block() and unblock().
     */
    public List<String> getAll() {
        return Collections.unmodifiableList(new ArrayList<>(blocked));
    }

    /** @return how many IPs are currently blocked */
    public int size() {
        return blocked.size();
    }

    /** @return true if nothing is blocked */
    public boolean isEmpty() {
        return blocked.isEmpty();
    }

    /** Removes every IP (used when the analyst resets a session). */
    public void clear() {
        blocked.clear();
    }
}