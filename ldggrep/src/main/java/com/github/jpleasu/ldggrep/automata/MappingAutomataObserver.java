package com.github.jpleasu.ldggrep.automata;

import java.util.*;
import java.util.Map.Entry;
import java.util.stream.Collectors;

import com.github.jpleasu.ldggrep.util.Pair;

import dk.brics.automaton.State;

/**
 * An observer that maintains the mapping of states to Pair objects used by LGDMatcher 
 *
 * @param <N> LDGMatcher node type
 */
public class MappingAutomataObserver<N> implements AutomataObserver {
	protected Map<State, Set<Pair<Integer, N>>> s2n = new HashMap<>();

	public MappingAutomataObserver(Map<Pair<Integer, N>, State> pairMap) {
		initialize(pairMap);
	}

	@Override
	public void merged(Map<State, Set<State>> m) {
		HashMap<State, Set<Pair<Integer, N>>> newStateToPairs = new HashMap<>();
		for (Entry<State, Set<State>> e : m.entrySet())
			newStateToPairs.put(e.getKey(),
				e.getValue()
						.stream()
						.flatMap(s -> s2n.getOrDefault(s, Collections.emptySet()).stream())
						.collect(Collectors.toSet()));
		s2n = newStateToPairs;
	}

	/**
	 *  initialize this map from its inverse
	 *  
	 * @param pairMap the inverse of s2n
	 */
	public void initialize(Map<Pair<Integer, N>, State> pairMap) {
		for (Entry<Pair<Integer, N>, State> e : pairMap.entrySet()) {
			s2n.computeIfAbsent(e.getValue(), (p) -> new HashSet<>()).add(e.getKey());
		}
	}

	public void retainAll(Set<State> liveStates) {
		s2n.keySet().retainAll(liveStates);
	}

	public void remove(State state) {
		s2n.remove(state);
	}

	public State newAcceptingState(Set<Pair<Integer, N>> pairs) {
		State ss = new State();
		ss.setAccept(true);
		s2n.put(ss, pairs);
		return ss;
	}

	public Map<State, Set<Pair<Integer, N>>> getMap() {
		return s2n;
	}

	public Set<Pair<Integer, N>> get(State state) {
		return s2n.get(state);
	}
}