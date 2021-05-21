package com.github.jpleasu.ldggrep;

import java.util.*;
import java.util.Map.Entry;
import java.util.function.Function;
import java.util.stream.Collectors;

import com.github.jpleasu.ldggrep.util.Pair;

import dk.brics.automaton.State;
import dk.brics.automaton.Transition;

/**
 * 
 * The result of {@link LDGMatcher#match(LDG)} - the meet of the LDG and predicate machine.
 * 
 * It is composed of 4 parts
 * 
 * 1) a minimized dk.brics Automaton
 * 2) s2n: a map from dk.brics states to sets of pairs, (predicate machine state, LDG node) - i.e. states of the determinized meet
 * 3) c2e: a map from labels of the dk.brics automaton to labels of the meet
 *
 * @param <N> node type
 * @param <E> edge type
 */
public class LDGMatch<N, E> {

	public Set<State> initialStates;
	public Set<State> finalStates;

	public Map<State, Set<Pair<Integer, N>>> s2ps;
	public Map<Integer, E> c2e;

	public Map<Integer, Set<N>> memory = new HashMap<>();

	@Override
	public String toString() {
		return String.format("{initial=%s, accepting=%s, s2n=%s, c2e=%s}", initialStates,
			finalStates, s2ps, c2e);
	}

	protected Set<N> project(Set<Pair<Integer, N>> pairs) {
		return pairs.stream().map(Pair::getRight).collect(Collectors.toSet());
	}

	protected Set<N> project(Collection<State> states) {
		return states.stream()
				.map(s2ps::get)
				.flatMap(Set::stream)
				.map(Pair::getRight)
				.collect(Collectors.toSet());
	}

	public Set<N> getInitialProjection() {
		return project(initialStates);
	}

	public Set<N> getFinallProjection() {
		return project(finalStates);
	}

	public Set<N> lookupProjection(State s) {
		return project(s2ps.get(s));
	}

	public void dump() {
		for (Entry<State, Set<Pair<Integer, N>>> e : s2ps.entrySet()) {
			State s = e.getKey();
			StringBuilder initialFinal = new StringBuilder();
			if (initialStates.contains(s)) {
				initialFinal.append("i");
			}
			if (finalStates.contains(s)) {
				initialFinal.append("f");
			}
			System.err.printf("[%s]%s:\n", initialFinal, e.getValue());
			for (Transition t : e.getKey().getTransitions()) {
				System.err.printf("  - %s -> %s\n", c2e.get(t.getMin()), s2ps.get(t.getDest()));
			}
		}
	}

	public void dump(LDGModel<N, E> model) {
		Function<Set<Pair<Integer, N>>, String> ps2s = s -> {
			return '{' + s.stream()
					.map(p -> Pair.of(p.getLeft(), model.nodeToString(p.getRight())).toString())
					.collect(Collectors.joining(",")) +
				'}';
		};

		for (Entry<State, Set<Pair<Integer, N>>> e : s2ps.entrySet()) {
			State s = e.getKey();
			StringBuilder be = new StringBuilder();
			if (initialStates.contains(s)) {
				be.append('i');
			}
			else {
				be.append(' ');
			}
			if (finalStates.contains(s)) {
				be.append('f');
			}
			else {
				be.append(' ');
			}
			System.err.printf("[%s]%s:\n", be, ps2s.apply(e.getValue()));
			for (Transition t : e.getKey().getTransitions()) {
				System.err.printf("  - %s -> %s\n", model.edgeToString(c2e.get(t.getMin())),
					ps2s.apply(s2ps.get(t.getDest())));
			}
		}
	}
}
