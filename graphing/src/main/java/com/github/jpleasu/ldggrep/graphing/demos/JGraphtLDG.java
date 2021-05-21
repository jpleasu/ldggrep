package com.github.jpleasu.ldggrep.graphing.demos;

import java.util.stream.Stream;

import org.jgrapht.graph.DirectedPseudograph;

import com.github.jpleasu.ldggrep.LDG;

class JGraphtLDG implements LDG<String, String> {
	final DirectedPseudograph<String, String> g;

	JGraphtLDG(DirectedPseudograph<String, String> g) {
		this.g = g;
	}

	@Override
	public Stream<String> startNodes() {
		return g.vertexSet().parallelStream();
	}

	@Override
	public Stream<String> outEdges(String n) {
		return g.outgoingEdgesOf(n).stream();
	}

	@Override
	public String targetNode(String e) {
		return g.getEdgeTarget(e);
	}
}