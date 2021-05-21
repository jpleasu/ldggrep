/**
 * 
 * LDGMatcher matches an ldggrep pattern against an LDG.
 * 
 * The algorithm is based on standard finite state machine intersection.  
 * States in the product automaton are visited from the initial state, 
 * preserving only those states (and transitions) that agree in the two machines.
 * 
 * There are two extensions.. 1) one of our machines is composed of predicate transitions, so the test for agreement is evaluation. 2) 
 * 
 */
package com.github.jpleasu.ldggrep;

import java.util.*;
import java.util.Map.Entry;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import com.github.jpleasu.ldggrep.automata.MappingAutomataObserver;
import com.github.jpleasu.ldggrep.internal.*;
import com.github.jpleasu.ldggrep.parser.Expr;
import com.github.jpleasu.ldggrep.util.Pair;

import dk.brics.automaton.*;

/**
 * compute a match object from an input graph.
 * 
 * The match is a graph of numbered-node sets with edge transitions
 * 
 * 
 * @param <N> the node type
 * @param <E> the edge type
 * 
 */
public class LDGMatcher<N, E> {
	final Expr expr;

	protected final LDGModel<N, E> model;
	protected final PredicateMachine<N, E> predicateMachine;

	public LDGMatcher(LDGModel<N, E> model, String pat) {
		this(model, Expr.parse(pat));
	}

	public LDGMatcher(LDGModel<N, E> model, Expr expr) {
		this.model = model;
		this.expr = expr;

		predicateMachine = new PredicateMachine<N, E>(model, expr);
	}

	final Map<E, Integer> e2c_ = new HashMap<>();
	final Map<Pair<Integer, N>, State> p2s_ = new HashMap<>();
	final Set<StatePair> eps = new HashSet<>();
	final Automaton matchFSM = new Automaton();

	public void clearMatchData() {
		e2c_.clear();
		p2s_.clear();
		eps.clear();

		// make a empty
		Automaton.setMinimizeAlways(false);
		Automaton.setAllowMutate(true);
		matchFSM.setInitialState(new State());
		matchFSM.setDeterministic(true);

		first_user_c = 0;

	}

	// transition labels that only occur from initial to starting node.
	int first_user_c;

	Integer e2c(E e) {
		return e2c_.computeIfAbsent(e, ee -> (e2c_.size() + first_user_c));
	}

	State p2s(Pair<Integer, N> p) {
		return p2s_.computeIfAbsent(p, pp -> new State());
	}

	boolean addEps(Pair<Integer, N> p0, Pair<Integer, N> p1) {
		return eps.add(new StatePair(p2s(p0), p2s(p1)));
	}

	boolean addTrans(E e, Pair<Integer, N> p0, Pair<Integer, N> p1) {
		return p2s(p0).addTransition(new Transition(e2c(e), p2s(p1)));
	}

	/**
	 * attempt to match the given graph
	 * 
	 * @param graph the graph to match
	 * @return the match found
	 */
	@SuppressWarnings("unchecked")
	public LDGMatch<N, E> match(LDG<N, E> graph) {
		clearMatchData();

		State s0 = matchFSM.getInitialState();

		Stream<N> startNodes = graph.startNodes();
		startNodes =
			Stream.concat(startNodes, model.incomingMemory.values().stream().flatMap(Set::stream));

		Set<Pair<Integer, N>> front =
			startNodes.map(n -> Pair.of(PredicateMachine.INITIAL_STATE, n))
					.collect(Collectors.toSet());

		for (Pair<Integer, N> p : front) {
			s0.addTransition(new Transition(first_user_c++, p2s(p)));
		}

		Set<Pair<Integer, N>> done = new HashSet<>();
		while (!front.isEmpty()) {
			Set<Pair<Integer, N>> newfront = new HashSet<>();
			for (Pair<Integer, N> p0 : front) {
				Integer i0 = p0.getLeft();
				N n0 = p0.getRight();

				for (Trans t : predicateMachine.transitionsFrom(i0)) {
					Integer i1 = t.target;

					if (t instanceof Eps) {
						Pair<Integer, N> p1;
						// epsilons advance only the predicate machine state
						p1 = Pair.of(i1, n0);
						newfront.add(p1);
						addEps(p0, p1);
					}
					else if (t instanceof NTrans) {
						Pair<Integer, N> p1;
						NTrans<N> x = (NTrans<N>) t;
						// state predicates advance only machine states that match the predicate
						if (x.p.matches(i0, n0)) {
							p1 = Pair.of(i1, n0);
							newfront.add(p1);
							addEps(p0, p1);
						}
					}
					else {
						ETrans<E> x = (ETrans<E>) t;
						graph.outEdges(n0).forEach(e -> {
							if (x.p.matches(i0, e)) {
								Pair<Integer, N> p1;
								p1 = Pair.of(i1, graph.targetNode(e));
								newfront.add(p1);
								addTrans(e, p0, p1);
							}
						});
					}
				}
			}
			done.addAll(front);
			newfront.removeAll(done);
			front = newfront;
		}

		// set accepters
		for (Pair<Integer, N> p : done) {
			if (p.getLeft().equals(PredicateMachine.FINAL_STATE))
				p2s(p).setAccept(true);
		}

		return minimizeAndCreateMatch(graph);
	}

	/**
	 * attempt to find a minimal match (intersection stops with the first round that reaches a terminal).
	 * 
	 * @param graph the graph to match
	 * @return the match found
	 */
	@SuppressWarnings("unchecked")
	public LDGMatch<N, E> minmatch(LDG<N, E> graph) {
		clearMatchData();

		State s0 = matchFSM.getInitialState();

		Stream<N> startNodes = graph.startNodes();
		startNodes =
			Stream.concat(startNodes, model.incomingMemory.values().stream().flatMap(Set::stream));

		Map<Pair<Integer, N>, Integer> distanceToNode = new HashMap<>();
		Set<Pair<Integer, N>> front =
			startNodes.map(n -> Pair.of(PredicateMachine.INITIAL_STATE, n))
					.collect(Collectors.toSet());

		for (Pair<Integer, N> p : front) {
			distanceToNode.put(p, 0);
			s0.addTransition(new Transition(first_user_c++, p2s(p)));
		}

		Set<Pair<Integer, N>> done = new HashSet<>();

		while (!front.isEmpty()) {
			Set<Pair<Integer, N>> newfront = new HashSet<>();
			for (Pair<Integer, N> p0 : front) {
				Integer i0 = p0.getLeft();
				N n0 = p0.getRight();

				for (Trans t : predicateMachine.transitionsFrom(i0)) {
					Integer i1 = t.target;
					if (t instanceof Eps) {
						Pair<Integer, N> p1;

						// epsilons advance only the predicate machine state
						newfront.add(p1 = Pair.of(i1, n0));
						addEps(p0, p1);
						distanceToNode.put(p1,
							Math.min(distanceToNode.getOrDefault(p1, Integer.MAX_VALUE),
								distanceToNode.get(p0)));
					}
					else if (t instanceof NTrans) {
						Pair<Integer, N> p1;

						NTrans<N> x = (NTrans<N>) t;
						// state predicates advance only machine states that match the predicate
						if (x.p.matches(i0, n0)) {
							newfront.add(p1 = Pair.of(i1, n0));
							addEps(p0, p1);
							distanceToNode.put(p1,
								Math.min(distanceToNode.getOrDefault(p1, Integer.MAX_VALUE),
									distanceToNode.get(p0)));
						}
					}
					else {
						ETrans<E> x = (ETrans<E>) t;
						graph.outEdges(n0).forEach(e -> {
							if (x.p.matches(i0, e)) {
								Pair<Integer, N> p1;

								newfront.add(p1 = Pair.of(i1, graph.targetNode(e)));
								addTrans(e, p0, p1);
								distanceToNode.put(p1,
									Math.min(distanceToNode.getOrDefault(p1, Integer.MAX_VALUE),
										1 + distanceToNode.get(p0)));
							}
						});
					}
				}
			}
			done.addAll(front);
			if (front.stream().anyMatch(p -> p.getLeft().equals(PredicateMachine.FINAL_STATE)))
				break;

			newfront.removeAll(done);
			front = newfront;
		}

		// set accepters
		Map<State, Integer> distanceToState = new HashMap<>();
		for (Entry<Pair<Integer, N>, State> e : p2s_.entrySet())
			distanceToState.put(e.getValue(), distanceToNode.get(e.getKey()));

		for (Pair<Integer, N> p : done) {
			State s = p2s(p);
			int dd = distanceToNode.get(p);
			s.getTransitions().removeIf(t -> distanceToState.get(t.getDest()) <= dd);
			if (p.getLeft().equals(PredicateMachine.FINAL_STATE))
				p2s(p).setAccept(true);
		}
		return minimizeAndCreateMatch(graph);
	}

	// assume match_fsm and maps have been computed, minimize the automaton and turn it into a Match
	// XXX: this only uses graph.target, and only in one place, where a sink accepting state is split apart 
	protected LDGMatch<N, E> minimizeAndCreateMatch(LDG<N, E> graph) {

		MappingAutomataObserver<N> mao = new MappingAutomataObserver<N>(p2s_);

		Map<Integer, E> c2e =
			e2c_.entrySet().stream().collect(Collectors.toMap(Entry::getValue, Entry::getKey));

		// save some memory
		e2c_.clear();
		p2s_.clear();

		BasicOperations.addEpsilonsAndRemoveDeadTransitions(matchFSM, eps, mao);
		BasicOperations.determinize_large_alphabet(matchFSM, mao);

		// save the initials before merging for use when splitting a final sink 
		Set<Pair<Integer, N>> preMergedInitials = matchFSM.getInitialState()
				.getTransitions()
				.stream()
				.map(t -> t.getDest())
				.map(mao::get)
				.flatMap(Set::stream)
				.collect(Collectors.toSet());

		//MinimizationOperations.minimizeHopcroft(matchFSM, mao);
		MinimizationOperations.minimizeHuffman(matchFSM, mao);

		matchFSM.unreduce();

		if (matchFSM.isEmpty())
			return null;

		// remove the proxy states
		Set<State> liveStates = matchFSM.getLiveStates();
		liveStates.remove(matchFSM.getInitialState());
		mao.retainAll(liveStates);

		LDGMatch<N, E> match = new LDGMatch<>();
		// initial transitions were labeled with a unique set of labels, so initial is fixed
		match.initialStates = matchFSM.getInitialState()
				.getTransitions()
				.stream()
				.map(t -> t.getDest())
				.collect(Collectors.toSet());

		// if there's an accepting state with no outgoing transitions, replace it 
		// (and its incoming transitions) with transitions to new singletons
		State finalSinkState = null;
		for (State s : matchFSM.getAcceptStates()) {
			if (s.getTransitions().isEmpty() && mao.get(s).size() > 1) {
				finalSinkState = s;
				break;
			}
		}

		if (finalSinkState != null) {
			Set<Pair<Integer, N>> finalSinkPairs = mao.get(finalSinkState);
			final Map<Set<Pair<Integer, N>>, State> newStates = new HashMap<>();
			final Function<Set<Pair<Integer, N>>, State> getstate =
				sop -> newStates.computeIfAbsent(sop, mao::newAcceptingState);

			for (State s0 : liveStates) {
				for (Transition t : s0.getTransitions()) {
					State s1 = t.getDest();
					if (finalSinkState.equals(s1)) {
						E e = c2e.get(t.getMin());
						N n1 = graph.targetNode(e);

						Set<Pair<Integer, N>> matchingPairs = finalSinkPairs.stream()
								.filter(p -> p.getRight().equals(n1))
								.collect(Collectors.toSet());
						State new_s1 = getstate.apply(matchingPairs);
						t.setDest(new_s1);
					}
				}
			}
			if (match.initialStates.contains(finalSinkState)) {
				match.initialStates.remove(finalSinkState);
				// grouped by node, create new states and make them the beginning states
				for (List<Pair<Integer, N>> finalPairs : finalSinkPairs.stream()
						.collect(Collectors.groupingBy(Pair::getRight))
						.values()) {
					if (preMergedInitials.containsAll(finalPairs)) {
						match.initialStates.add(getstate.apply(new HashSet<>(finalPairs)));
					}
				}
			}

			mao.remove(finalSinkState);
		}

		match.finalStates = matchFSM.getAcceptStatesFrom(match.initialStates);

		match.s2ps = mao.getMap();
		match.c2e =
			c2e.entrySet().stream().collect(Collectors.toMap(Entry::getKey, e -> e.getValue()));

		model.copyOutgoingMemory(match);
		return match;
	}

}
