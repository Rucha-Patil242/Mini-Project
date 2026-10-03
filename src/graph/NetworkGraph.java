package graph;

import java.util.*;

public class NetworkGraph{
    private final Map<String, List<String>> adj = new LinkedHashMap<>();

    public void addEdge(String src, String dst){
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

    public List<String> getNeighbors(String node){
        if (adj.containsKey(node)) {
        return adj.get(node);
        }

        return new ArrayList<>();
    }

    public Set<String> getNodes(){
        return adj.keySet();
    }

    public void print(){
        for (String node : adj.keySet()) {
        System.out.println(node + " -> " + adj.get(node));
    }

    }
}