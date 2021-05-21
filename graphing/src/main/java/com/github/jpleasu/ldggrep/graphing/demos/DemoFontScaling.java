package com.github.jpleasu.ldggrep.graphing.demos;

import static com.github.jpleasu.ldggrep.graphing.demos.DemoUtil.*;

import java.util.function.Supplier;

import org.jgrapht.generate.GnmRandomGraphGenerator;
import org.jgrapht.graph.DirectedPseudograph;

import com.github.jpleasu.ldggrep.*;
import com.github.jpleasu.ldggrep.graphing.Util;

/**
 * demonstrate bad behavior of text scaling relative to vertex shape
 * in some environments.
 */
public class DemoFontScaling {
	static void createRandomGraph(DirectedPseudograph<String, String> g) {
		GnmRandomGraphGenerator<String, String> generator =
			new GnmRandomGraphGenerator<>(10, 15, 0l, false, true);
		generator.generateGraph(g);
	}

	public static void main(String[] args) {

		Supplier<String> nodeSupplier = new StringSupplier("abc").andThen(s -> s.repeat(20));
		Supplier<String> edgeSupplier = new StringSupplier("xyz");
		LDGModel<String, String> model = new LDGModel<>();
		DirectedPseudograph<String, String> g =
			new DirectedPseudograph<>(nodeSupplier, edgeSupplier, false);

		LDGMatcher<String, String> matcher;
		createRandomGraph(g);
		matcher = new LDGMatcher<>(model, "</^c*$/>. * </^(bc)*$/>");

		JGraphtLDG graph = new JGraphtLDG(g);
		LDGMatch<String, String> match = matcher.match(graph);
		Util.showJungrapht(model, match, "demo");
	}
}
