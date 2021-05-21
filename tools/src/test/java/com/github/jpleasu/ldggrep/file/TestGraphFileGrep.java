package com.github.jpleasu.ldggrep.file;

import static org.junit.jupiter.api.Assertions.*;

import java.io.File;
import java.util.Set;
import java.util.stream.Collectors;

import org.jgrapht.Graph;
import org.junit.jupiter.api.Test;

import com.github.jpleasu.ldggrep.LDGMatch;
import com.github.jpleasu.ldggrep.LDGModel;
import com.github.jpleasu.ldggrep.graphing.Util;
import com.github.jpleasu.ldggrep.graphing.Util.JgtMatchEdge;
import com.github.jpleasu.ldggrep.util.Pair;

public class TestGraphFileGrep {
	String DOT_FILE = "test.dot";

	File loadResource(String fileName) {
		ClassLoader classLoader = getClass().getClassLoader();
		return new File(classLoader.getResource(fileName).getFile());
	}

	@Test
	public void testDOTImporterModel() {
		File file = loadResource(DOT_FILE);
		assertTrue(file.exists());

		GraphFileLDG graph = new GraphFileLDG(file.getAbsolutePath());

		LDGModel<Node, Edge> model = new LDGModel<>();

		//  a -x-> b -y-> c
		//  ^-----x------/
		Set<String> startNodeNames =
			graph.startNodes().map(n -> n.name).collect(Collectors.toSet());

		assertEquals(Set.of("a", "b", "c"), startNodeNames);

		// verify that each node has one edge leaving it:
		graph.startNodes().forEach(n -> {
			assertEquals(1, graph.outEdges(n).count());
		});

		// get the "a" node
		Node anode = graph.startNodes().filter(n -> n.name.equals("a")).findFirst().get();
		assertEquals("x", graph.outEdges(anode).findFirst().get().label);

		// get the "b" node
		Node bnode = graph.startNodes().filter(n -> n.name.equals("b")).findFirst().get();
		assertEquals("y", graph.outEdges(bnode).findFirst().get().label);

		// get the "c" node
		Node cnode = graph.startNodes().filter(n -> n.name.equals("c")).findFirst().get();
		assertEquals("x", graph.outEdges(cnode).findFirst().get().label);

		GraphFileMatcher matcher = new GraphFileMatcher(model, "</a/> .");
		LDGMatch<Node, Edge> match = matcher.match(graph);
		assertNotNull(match);

		Graph<Set<Pair<Integer, Node>>, JgtMatchEdge<Node, Edge>> g = Util.toGraph(model, match);

		Set<Set<Pair<Integer, Node>>> anodes = g.vertexSet()
				.stream()
				.filter(s -> s.stream().anyMatch(p -> p.getRight().name.equals("a")))
				.collect(Collectors.toSet());
		// only one macro-node matches
		assertEquals(1, anodes.size());

		// that macro-node has only one thing in it
	}
}
