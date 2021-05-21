package com.github.jpleasu.ldggrep.ghidra.gui;

import java.util.*;

import com.github.jpleasu.ldggrep.LDGMatch;
import com.github.jpleasu.ldggrep.LDGModel;
import com.github.jpleasu.ldggrep.graphing.JgtGraphBuilder;
import com.github.jpleasu.ldggrep.util.Pair;

import ghidra.service.graph.AttributedEdge;
import ghidra.service.graph.AttributedVertex;

import java.util.stream.Collectors;

public class GhidraJgtGraphBuilder<N, E>
		extends JgtGraphBuilder<N, E, AttributedVertex, AttributedEdge> {

	final Map<String, E> etid2e = new HashMap<>();
	final Map<String, Set<Pair<Integer, N>>> vtid2ps = new HashMap<>();
	static String FINAL_ATTR_NAME = "final_state";
	static String INITIAL_ATTR_NAME = "initial_state";

	final Set<Set<Pair<Integer, N>>> initialps;
	final Set<Set<Pair<Integer, N>>> finalps;

	public GhidraJgtGraphBuilder(LDGModel<N, E> model, LDGMatch<N, E> match) {
		super(model, match);

		initialps = match.initialStates.stream().map(match.s2ps::get).collect(Collectors.toSet());
		finalps = match.finalStates.stream().map(match.s2ps::get).collect(Collectors.toSet());
	}

	@Override
	protected AttributedVertex ps2vt(Set<Pair<Integer, N>> ps) {
		String vertexId = Integer.toString(ps.hashCode());
		Set<String> names = new HashSet<>();
		for (Pair<Integer, N> p : ps)
			names.add(model.nodeToString(p.getRight()));
		StringBuilder sb = new StringBuilder();
		for (String name : names)
			sb.append("," + name);
		AttributedVertex vt;
		if (sb.length() == 0)
			vt = new AttributedVertex(vertexId, vertexId);
		else
			vt = new AttributedVertex(vertexId, sb.substring(1));
		if (vtid2ps.putIfAbsent(vertexId, ps) == null) {
			if (initialps.contains(ps)) {
				vt.setAttribute(INITIAL_ATTR_NAME, "true");
			}
			if (finalps.contains(ps)) {
				vt.setAttribute(FINAL_ATTR_NAME, "true");
			}

		}
		return vt;
	}

	@Override
	protected AttributedEdge newet(Set<Pair<Integer, N>> n0, Set<Pair<Integer, N>> n1, E e) {
		AttributedEdge et = new AttributedEdge(Integer.toString(etid2e.size()));
		etid2e.put(et.getId(), e);
		return et;
	}

}
