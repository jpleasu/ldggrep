package com.github.jpleasu.ldggrep.graphing.demos;

import java.util.function.Supplier;

import org.jgrapht.generate.GnmRandomGraphGenerator;
import org.jgrapht.graph.DirectedPseudograph;

import com.github.jpleasu.ldggrep.*;
import com.github.jpleasu.ldggrep.graphing.Util;
import com.github.jpleasu.ldggrep.graphing.demos.DemoUtil.StringSupplier;

/**
 * demonstrate basic render of a match.
 */
public class DemoRandom {
	static void createRandomGraph(DirectedPseudograph<String, String> g) {
		GnmRandomGraphGenerator<String, String> generator =
			new GnmRandomGraphGenerator<>(10, 15, 0l, false, true);
		generator.generateGraph(g);
	}

	public static void main(String[] args) {
		Supplier<String> nodeSupplier = new StringSupplier("abc");
		Supplier<String> edgeSupplier = new StringSupplier("xyz");
		LDGModel<String, String> model = new LDGModel<>();
		DirectedPseudograph<String, String> g =
			new DirectedPseudograph<>(nodeSupplier, edgeSupplier, false);

		LDGMatcher<String, String> matcher;
		createRandomGraph(g);
		matcher = new LDGMatcher<>(model, "<\"a\"> /x|y/* </^(bb|c)$/>");

		JGraphtLDG graph = new JGraphtLDG(g);
		LDGMatch<String, String> match = matcher.match(graph);
		Util.showJungrapht(model, match, "demo");
	}
}
