package com.github.jpleasu.ldggrep.rest;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.google.gson.annotations.Expose;

class Graph {
	@Expose
	List<Node> nodes = new ArrayList<>();
	@Expose
	List<Edge> edges = new ArrayList<>();

	boolean wired = false;

	void wire() {
		if (wired)
			return;
		final Map<String, Node> nmap = new HashMap<>();
		for (Node n : nodes) {
			nmap.put(n.id, n);
			n.outedges = new ArrayList<>();
		}
		for (Edge e : edges) {
			Node src = nmap.get(e.srcid);
			src.outedges.add(e);
			e.dst = nmap.get(e.dstid);
		}

		wired = true;

	}
}