package com.github.jpleasu.ldggrep.internal;

import static org.junit.jupiter.api.Assertions.*;

import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;

import com.github.jpleasu.ldggrep.*;
import com.github.jpleasu.ldggrep.util.Pair;

import dk.brics.automaton.State;
import dk.brics.automaton.Transition;

public class TestMatcher {

	static class Node {
		final int i;

		Node(int i) {
			this.i = i;
		}

		@Override
		public int hashCode() {
			return this.i;
		}

		@Override
		public boolean equals(Object obj) {
			return obj instanceof Node && ((Node) obj).i == i;
		}
	}

	static class Edge {
		final Node from, to;

		Edge(Node from, Node to) {
			this.from = from;
			this.to = to;
		}

		@Override
		public int hashCode() {
			return 31 * from.i + to.i;
		}

		@Override
		public boolean equals(Object obj) {
			return obj instanceof Edge && ((Edge) obj).from == from && ((Edge) obj).to == to;
		}
	}

	public static class TestGraph implements LDG<Node, Edge> {
		private Map<Integer, Node> i2n = new HashMap<>();

		Set<Edge> edges = new HashSet<>();

		@Override
		public Stream<Node> startNodes() {
			return i2n.values().parallelStream();
		}

		@Override
		public Stream<Edge> outEdges(Node n) {
			return edges.stream().filter(e -> e.from.i == n.i);
		}

		@Override
		public Node targetNode(Edge e) {
			return e.to;
		}

		Node node(int i) {
			return i2n.computeIfAbsent(i, Node::new);
		}

		Edge addEdge(int from, int to) {
			Edge e;
			edges.add(e = new Edge(node(from), node(to)));
			return e;
		}

	}

	public static class TestModel extends LDGModel<Node, Edge> {
		@NPred
		public boolean is0(Node n) {
			return 0 == n.i;
		}

		@Override
		public String nodeToString(Node n) {
			return Integer.toString(n.i);
		}

		@Override
		public String edgeToString(Edge e) {
			return String.format("[%d->%d]", e.from.i, e.to.i);
		}
	}

	@Test
	void test_basic_operation() {
		TestModel model = new TestModel();
		TestGraph g = new TestGraph();
		g.addEdge(0, 1);
		g.addEdge(1, 0);

		LDGMatcher<Node, Edge> matcher = new LDGMatcher<>(model, "</0/> .");
		LDGMatch<Node, Edge> m = matcher.match(g);
		assertNotNull(m);

		assertEquals(1, m.initialStates.size());

		State initialState = m.initialStates.iterator().next();
		Set<Pair<Integer, Node>> beginPairs = m.s2ps.get(initialState);

		// "0" before and after </0/> match
		assertEquals(2, beginPairs.size());
		Set<Node> initials = beginPairs.stream().map(Pair::getRight).collect(Collectors.toSet());

		assertEquals(1, initials.size());
		assertEquals(0, initials.iterator().next().i);

		assertEquals(1, initialState.getTransitions().size());

		Transition t = initialState.getTransitions().iterator().next();
		Edge e = m.c2e.get(t.getMin());
		assertEquals(0, e.from.i);
		assertEquals(1, e.to.i);

		State nextState = t.getDest();
		assertTrue(m.finalStates.contains(nextState));
		Set<Pair<Integer, Node>> nextPairs = m.s2ps.get(nextState);

		assertEquals(1, nextPairs.size());

		assertEquals(1, nextPairs.iterator().next().getRight().i);
	}

	@Test
	void test_final_merging_initials() {
		TestModel model = new TestModel();
		TestGraph g = new TestGraph();
		g.addEdge(0, 1);
		g.addEdge(1, 2);
		g.node(3);

		// prior to filtering with preMergedInitials, 2 is merged with 3 in the final sink state.  3 is marked initial though, so 2 got the same mark.
		LDGMatcher<Node, Edge> matcher = new LDGMatcher<>(model, "</0|3/> .*");
		LDGMatch<Node, Edge> m = matcher.match(g);
		assertNotNull(m);
		assertTrue(m.getInitialProjection().stream().noneMatch(n -> n.i == 2));
	}

	@Test
	void test_sto() {
		TestModel model = new TestModel();
		TestGraph g = new TestGraph();
		g.addEdge(0, 1);
		g.addEdge(1, 0);

		LDGMatcher<Node, Edge> matcher = new LDGMatcher<>(model, "</0/><sto(0)> . <sto(1)>");
		LDGMatch<Node, Edge> m = matcher.match(g);
		assertNotNull(m);

		assertTrue(m.memory.containsKey(0));
		assertEquals(0, m.memory.get(0).iterator().next().i);

		assertTrue(m.memory.containsKey(1));
		assertEquals(1, m.memory.get(1).iterator().next().i);
	}

	@Test
	void test_mem() {
		TestModel model = new TestModel();
		TestGraph g = new TestGraph();
		g.addEdge(0, 1);
		g.addEdge(1, 0);
		model.setIncomingMemory(Map.of(0, Set.of(g.node(0)), 1, Set.of(g.node(1))));

		LDGMatcher<Node, Edge> matcher = new LDGMatcher<>(model, "<mem(0)> . <mem(1)>");
		LDGMatch<Node, Edge> m = matcher.match(g);
		assertNotNull(m);

		assertTrue(m.getInitialProjection().equals(Set.of(g.node(0))));
		assertTrue(m.getFinallProjection().equals(Set.of(g.node(1))));
	}

	@Test
	void test_starting_gen() {
		TestModel model = new TestModel();
		TestGraph g = new TestGraph();
		g.addEdge(0, 1);
		g.addEdge(0, 2);
		g.addEdge(1, 2);
		g.addEdge(2, 3);

		final String PAT = "<is0> /2/";

		LDGMatch<Node, Edge> m;
		Set<Transition> trans;

		m = new LDGMatcher<>(model, PAT).match(g);
		assertNotNull(m);
		assertEquals(Set.of(g.node(0)), m.getInitialProjection());
		trans = m.initialStates.iterator().next().getTransitions();
		assertEquals(1, trans.size());

		AtomicBoolean b = new AtomicBoolean(false);
		TestModel model2 = new TestModel() {
			@StartGen("is0")
			Stream<Node> gen0(TestGraph graph) {
				b.set(true);
				return Stream.of(graph.node(0));
			}
		};
		m = new LDGMatcher<>(model2, PAT).match(g);
		// we must have hit the startgen
		assertTrue(b.get());

		assertNotNull(m);
		assertEquals(Set.of(g.node(0)), m.getInitialProjection());
		trans = m.initialStates.iterator().next().getTransitions();
		assertEquals(1, trans.size());

	}

}
