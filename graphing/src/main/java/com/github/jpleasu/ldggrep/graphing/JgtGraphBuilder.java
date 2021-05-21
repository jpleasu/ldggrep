package com.github.jpleasu.ldggrep.graphing;

import java.util.Set;
import java.util.Map.Entry;

import org.jgrapht.Graph;
import org.jgrapht.graph.AbstractBaseGraph;
import org.jgrapht.graph.DirectedPseudograph;

import com.github.jpleasu.ldggrep.LDGMatch;
import com.github.jpleasu.ldggrep.LDGModel;
import com.github.jpleasu.ldggrep.util.Pair;

import dk.brics.automaton.State;
import dk.brics.automaton.Transition;

public abstract class JgtGraphBuilder<N, E, VertexT, EdgeT> {
	final protected LDGModel<N, E> model;
	final protected LDGMatch<N, E> match;

	// JGraphT are distinguishable across the whole graph, while LDGGrep edges are only
	// distinguishable up to source
	protected abstract EdgeT newet(Set<Pair<Integer, N>> ps0, Set<Pair<Integer, N>> ps1, E e);

	protected abstract VertexT ps2vt(Set<Pair<Integer, N>> ps);

	public JgtGraphBuilder(LDGModel<N, E> model, LDGMatch<N, E> match) {
		this.model = model;
		this.match = match;
	}

	public Graph<VertexT, EdgeT> buildGraph() {
		DirectedPseudograph<VertexT, EdgeT> g = new DirectedPseudograph<>(null, null, false);
		return buildGraph(g);
	}

	public Graph<VertexT, EdgeT> buildGraph(AbstractBaseGraph<VertexT, EdgeT> g) {
		for (Set<Pair<Integer, N>> ps : match.s2ps.values()) {
			g.addVertex(ps2vt(ps));
		}

		for (Entry<State, Set<Pair<Integer, N>>> e : match.s2ps.entrySet()) {
			State s = e.getKey();
			Set<Pair<Integer, N>> ps0 = e.getValue();
			VertexT vt0 = ps2vt(ps0);
			for (Transition t : s.getTransitions()) {
				Set<Pair<Integer, N>> ps1 = match.s2ps.get(t.getDest());
				for (int c = t.getMin(); c <= t.getMax(); ++c) {
					g.addEdge(vt0, ps2vt(ps1), newet(ps0, ps1, match.c2e.get(c)));
				}
			}
		}
		return g;
	}

}
