package core;

import model.Alert;
import model.Severity;

import java.util.Stack;

/**
 * Blocks and unblocks IPs.
 * - Stack: records each successful block so undo() reverts the most recent one (LIFO).
 */
public class ResponseEngine {

    private final BlockList blockList;
    private final Stack<String> undoStack = new Stack<>();

    public ResponseEngine(BlockList blockList) {
        this.blockList = blockList;
    }

    /**
     * Blocks an IP. Only recorded for undo if it was not already blocked.
     * @return true if newly blocked, false otherwise.
     */
    public boolean block(String ip) {
        if (blockList.block(ip)) {
            undoStack.push(ip.trim());
            return true;
        }
        return false;
    }

    /**
     * Reverts the most recent successful block.
     * @return the unblocked IP, or null if there is nothing to undo.
     */
    public String undo() {
        if (undoStack.isEmpty()) return null;
        String ip = undoStack.pop();
        blockList.unblock(ip);
        return ip;
    }

    /**
     * Auto-blocks on HIGH or CRITICAL alerts.
     * @return true if an IP was newly blocked.
     */
    public boolean handleAlert(Alert alert) {
        if (alert == null) return false;
        Severity s = alert.getseverity();
        if (s == Severity.HIGH || s == Severity.CRITICAL) {
            return block(alert.getip());
        }
        return false;
    }

    public boolean isBlocked(String ip) {
        return blockList.isBlocked(ip);
    }

    public BlockList getBlockList() {
        return blockList;
    }
}