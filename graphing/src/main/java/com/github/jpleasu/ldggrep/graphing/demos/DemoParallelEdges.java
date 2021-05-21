package com.github.jpleasu.ldggrep.graphing.demos;

import java.util.function.Supplier;

import org.jgrapht.graph.DirectedPseudograph;

import com.github.jpleasu.ldggrep.*;
import com.github.jpleasu.ldggrep.graphing.Util;
import com.github.jpleasu.ldggrep.graphing.demos.DemoUtil.StringSupplier;

/**
 * demonstrate bad behavior of edge label placement with a large number
 * of parallel edges at some zoom levels.
 */
public class DemoParallelEdges {

	static void createParallelEdgeGraph(DirectedPseudograph<String, String> g) {
		String v0 = g.addVertex();
		String v1 = g.addVertex();
		for (int i = 0; i < 13; ++i) {
			g.addEdge(v0, v1);
		}
	}

	public static void main(String[] args) {

		Supplier<String> nodeSupplier = new StringSupplier("abc");
		Supplier<String> edgeSupplier = new StringSupplier("xyz");

		LDGModel<String, String> model = new LDGModel<>();
		DirectedPseudograph<String, String> g =
			new DirectedPseudograph<>(nodeSupplier, edgeSupplier, false);

		LDGMatcher<String, String> matcher;
		createParallelEdgeGraph(g);
		matcher = new LDGMatcher<>(model, "</a/> . </b/>");

		JGraphtLDG graph = new JGraphtLDG(g);
		LDGMatch<String, String> match = matcher.match(graph);
		Util.showJungrapht(model, match, "demo");
	}
}
