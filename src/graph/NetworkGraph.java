package graph;

import java.util.*;

public class NetworkGraph {
    private final Map<String, List<String>> adj = new LinkedHashMap<>();

    public void addEdge(String src, String dst) {
        if (!adj.containsKey(src)) {
            adj.put(src, new ArrayList<>());
        }
        if (!adj.containsKey(dst)) {
            adj.put(dst, new ArrayList<>());
        }
        if (!adj.get(src).contains(dst)) {
            adj.get(src).add(dst);
        }

    }

    public List<String> getNeighbors(String node) {
        if (adj.containsKey(node)) {
            return adj.get(node);
        }

        return new ArrayList<>();
    }

    public Set<String> getNodes() {
        return adj.keySet();
    }

    public void print() {
        for (String node : adj.keySet()) {
            System.out.println(node + " -> " + adj.get(node));
        }
    }

    public List<String> bfs(String start) {
        List<String> order = new ArrayList<>();
        if (!adj.containsKey(start)) {
            return order; 
        }

        Set<String> visited = new HashSet<>();
        Queue<String> queue = new LinkedList<>();

        queue.add(start);
        visited.add(start);

        while (!queue.isEmpty()) {
            String cur = queue.poll(); 
            order.add(cur);
            for (String next : adj.get(cur)) {
                if (!visited.contains(next)) {
                    visited.add(next);
                    queue.add(next);
                }
            }
        }
        return order;
    }

    public List<String> dfsPath(String start, String target) {
        List<String> path = new ArrayList<>();
        if (!adj.containsKey(start) || !adj.containsKey(target)) {
            return path; 
        }
        dfs(start, target, new HashSet<>(), path);
        return path; 
    }

    private boolean dfs(String cur, String target, Set<String> visited, List<String> path) {
        visited.add(cur);
        path.add(cur); 

        if (cur.equals(target)) {
            return true; 
        }

        for (String next : adj.get(cur)) {
            if (!visited.contains(next)) {
                if (dfs(next, target, visited, path)) {
                    return true; 
                }
            }
        }

        path.remove(path.size() - 1); 
        return false;
    }

}