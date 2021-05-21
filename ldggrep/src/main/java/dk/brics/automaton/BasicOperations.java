/*
 * dk.brics.automaton
 * 
 * Copyright (c) 2001-2017 Anders Moeller
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Modifications for ldggrep:
 * - label type goes from char to int
 * - add determinization algorithm for automata with large alphabets
 * - consolidate operations into a single method to save memory (addEpsilonsAndRemoveDeadTransitions)
 */

package dk.brics.automaton;

import java.util.ArrayList;
import java.util.BitSet;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.stream.Collectors;

import com.github.jpleasu.ldggrep.automata.AutomataObserver;

/**
 * Basic automata operations.
 */
final public class BasicOperations {
	
	private BasicOperations() {}

	/** 
	 * Returns an automaton that accepts the concatenation of the languages of 
	 * the given automata. 
	 * <p>
	 * Complexity: linear in number of states. 
	 */
	static public Automaton concatenate(Automaton a1, Automaton a2) {
		if (a1.isSingleton() && a2.isSingleton())
			return BasicAutomata.makeString(a1.singleton + a2.singleton);
		if (isEmpty(a1) || isEmpty(a2))
			return BasicAutomata.makeEmpty();
		boolean deterministic = a1.isSingleton() && a2.isDeterministic();
		if (a1 == a2) {
			a1 = a1.cloneExpanded();
			a2 = a2.cloneExpanded();
		} else {
			a1 = a1.cloneExpandedIfRequired();
			a2 = a2.cloneExpandedIfRequired();
		}
		for (State s : a1.getAcceptStates()) {
			s.accept = false;
			s.addEpsilon(a2.initial);
		}
		a1.deterministic = deterministic;
		a1.clearHashCode();
		a1.checkMinimizeAlways();
		return a1;
	}
	
	/**
	 * Returns an automaton that accepts the concatenation of the languages of
	 * the given automata.
	 * <p>
	 * Complexity: linear in total number of states.
	 */
	static public Automaton concatenate(List<Automaton> l) {
		if (l.isEmpty())
			return BasicAutomata.makeEmptyString();
		boolean all_singleton = true;
		for (Automaton a : l)
			if (!a.isSingleton()) {
				all_singleton = false;
				break;
			}
		if (all_singleton) {
			StringBuilder b = new StringBuilder();
			for (Automaton a : l)
				b.append(a.singleton);
			return BasicAutomata.makeString(b.toString());
		} else {
			for (Automaton a : l)
				if (a.isEmpty())
					return BasicAutomata.makeEmpty();
			Set<Integer> ids = new HashSet<Integer>();
			for (Automaton a : l)
				ids.add(System.identityHashCode(a));
			boolean has_aliases = ids.size() != l.size();
			Automaton b = l.get(0);
			if (has_aliases)
				b = b.cloneExpanded();
			else
				b = b.cloneExpandedIfRequired();
			Set<State> ac = b.getAcceptStates();
			boolean first = true;
			for (Automaton a : l)
				if (first)
					first = false;
				else {
					if (a.isEmptyString())
						continue;
					Automaton aa = a;
					if (has_aliases)
						aa = aa.cloneExpanded();
					else
						aa = aa.cloneExpandedIfRequired();
					Set<State> ns = aa.getAcceptStates();
					for (State s : ac) {
						s.accept = false;
						s.addEpsilon(aa.initial);
						if (s.accept)
							ns.add(s);
					}
					ac = ns;
				}
			b.deterministic = false;
			b.clearHashCode();
			b.checkMinimizeAlways();
			return b;
		}
	}

	/**
	 * Returns an automaton that accepts the union of the empty string and the
	 * language of the given automaton.
	 * <p>
	 * Complexity: linear in number of states.
	 */
	static public Automaton optional(Automaton a) {
		a = a.cloneExpandedIfRequired();
		State s = new State();
		s.addEpsilon(a.initial);
		s.accept = true;
		a.initial = s;
		a.deterministic = false;
		a.clearHashCode();
		a.checkMinimizeAlways();
		return a;
	}
	
	/**
	 * Returns an automaton that accepts the Kleene star (zero or more
	 * concatenated repetitions) of the language of the given automaton.
	 * Never modifies the input automaton language.
	 * <p>
	 * Complexity: linear in number of states.
	 */
	static public Automaton repeat(Automaton a) {
		a = a.cloneExpanded();
		State s = new State();
		s.accept = true;
		s.addEpsilon(a.initial);
		for (State p : a.getAcceptStates())
			p.addEpsilon(s);
		a.initial = s;
		a.deterministic = false;
		a.clearHashCode();
		a.checkMinimizeAlways();
		return a;
	}

	/**
	 * Returns an automaton that accepts <code>min</code> or more
	 * concatenated repetitions of the language of the given automaton.
	 * <p>
	 * Complexity: linear in number of states and in <code>min</code>.
	 */
	static public Automaton repeat(Automaton a, int min) {
		if (min == 0)
			return repeat(a);
		List<Automaton> as = new ArrayList<Automaton>();
		while (min-- > 0)
			as.add(a);
		as.add(repeat(a));
		return concatenate(as);
	}
	
	/**
	 * Returns an automaton that accepts between <code>min</code> and
	 * <code>max</code> (including both) concatenated repetitions of the
	 * language of the given automaton.
	 * <p>
	 * Complexity: linear in number of states and in <code>min</code> and
	 * <code>max</code>.
	 */
	static public Automaton repeat(Automaton a, int min, int max) {
		if (min > max)
			return BasicAutomata.makeEmpty();
		max -= min;
		a.expandSingleton();
		Automaton b;
		if (min == 0)
			b = BasicAutomata.makeEmptyString();
		else if (min == 1)
			b = a.clone();
		else {
			List<Automaton> as = new ArrayList<Automaton>();
			while (min-- > 0)
				as.add(a);
			b = concatenate(as);
		}
		if (max > 0) {
			Automaton d = a.clone();
			while (--max > 0) {
				Automaton c = a.clone();
				for (State p : c.getAcceptStates())
					p.addEpsilon(d.initial);
				d = c;
			}
			for (State p : b.getAcceptStates())
				p.addEpsilon(d.initial);
			b.deterministic = false;
			b.clearHashCode();
			b.checkMinimizeAlways();
		}
		return b;
	}

	/**
	 * Returns a (deterministic) automaton that accepts the complement of the
	 * language of the given automaton.
	 * <p>
	 * Complexity: linear in number of states (if already deterministic).
	 */
	static public Automaton complement(Automaton a) {
		a = a.cloneExpandedIfRequired();
		a.determinize();
		a.totalize();
		for (State p : a.getStates())
			p.accept = !p.accept;
		a.removeDeadTransitions();
		return a;
	}

	/**
	 * Returns a (deterministic) automaton that accepts the intersection of
	 * the language of <code>a1</code> and the complement of the language of 
	 * <code>a2</code>. As a side-effect, the automata may be determinized, if not
	 * already deterministic.
	 * <p>
	 * Complexity: quadratic in number of states (if already deterministic).
	 */
	static public Automaton minus(Automaton a1, Automaton a2) {
		if (a1.isEmpty() || a1 == a2)
			return BasicAutomata.makeEmpty();
		if (a2.isEmpty())
			return a1.cloneIfRequired();
		if (a1.isSingleton()) {
			if (a2.run(a1.singleton))
				return BasicAutomata.makeEmpty();
			else
				return a1.cloneIfRequired();
		}
		return intersection(a1, a2.complement());
	}

	/**
	 * Returns an automaton that accepts the intersection of
	 * the languages of the given automata. 
	 * Never modifies the input automata languages.
	 * <p>
	 * Complexity: quadratic in number of states.
	 */
	static public Automaton intersection(Automaton a1, Automaton a2) {
		if (a1.isSingleton()) {
			if (a2.run(a1.singleton))
				return a1.cloneIfRequired();
			else
				return BasicAutomata.makeEmpty();
		}
		if (a2.isSingleton()) {
			if (a1.run(a2.singleton))
				return a2.cloneIfRequired();
			else
				return BasicAutomata.makeEmpty();
		}
		if (a1 == a2)
			return a1.cloneIfRequired();
		Transition[][] transitions1 = Automaton.getSortedTransitions(a1.getStates());
		Transition[][] transitions2 = Automaton.getSortedTransitions(a2.getStates());
		Automaton c = new Automaton();
		LinkedList<StatePair> worklist = new LinkedList<StatePair>();
		HashMap<StatePair, StatePair> newstates = new HashMap<StatePair, StatePair>();
		StatePair p = new StatePair(c.initial, a1.initial, a2.initial);
		worklist.add(p);
		newstates.put(p, p);
		while (worklist.size() > 0) {
			p = worklist.removeFirst();
			p.s.accept = p.s1.accept && p.s2.accept;
			Transition[] t1 = transitions1[p.s1.number];
			Transition[] t2 = transitions2[p.s2.number];
			for (int n1 = 0, b2 = 0; n1 < t1.length; n1++) {
				while (b2 < t2.length && t2[b2].max < t1[n1].min)
					b2++;
				for (int n2 = b2; n2 < t2.length && t1[n1].max >= t2[n2].min; n2++) 
					if (t2[n2].max >= t1[n1].min) {
						StatePair q = new StatePair(t1[n1].to, t2[n2].to);
						StatePair r = newstates.get(q);
						if (r == null) {
							q.s = new State();
							worklist.add(q);
							newstates.put(q, q);
							r = q;
						}
						int min = t1[n1].min > t2[n2].min ? t1[n1].min : t2[n2].min;
						int max = t1[n1].max < t2[n2].max ? t1[n1].max : t2[n2].max;
						p.s.transitions.add(new Transition(min, max, r.s));
					}
			}
		}
		c.deterministic = a1.deterministic && a2.deterministic;
		c.removeDeadTransitions();
		c.checkMinimizeAlways();
		return c;
	}
		
	/**
	 * Returns true if the language of <code>a1</code> is a subset of the
	 * language of <code>a2</code>. 
	 * As a side-effect, <code>a2</code> is determinized if not already marked as
	 * deterministic.
	 * <p>
	 * Complexity: quadratic in number of states.
	 */
	public static boolean subsetOf(Automaton a1, Automaton a2) {
		if (a1 == a2)
			return true;
		if (a1.isSingleton()) {
			if (a2.isSingleton())
				return a1.singleton.equals(a2.singleton);
			return a2.run(a1.singleton);
		}
		a2.determinize();
		Transition[][] transitions1 = Automaton.getSortedTransitions(a1.getStates());
		Transition[][] transitions2 = Automaton.getSortedTransitions(a2.getStates());
		LinkedList<StatePair> worklist = new LinkedList<StatePair>();
		HashSet<StatePair> visited = new HashSet<StatePair>();
		StatePair p = new StatePair(a1.initial, a2.initial);
		worklist.add(p);
		visited.add(p);
		while (worklist.size() > 0) {
			p = worklist.removeFirst();
			if (p.s1.accept && !p.s2.accept)
				return false;
			Transition[] t1 = transitions1[p.s1.number];
			Transition[] t2 = transitions2[p.s2.number];
			for (int n1 = 0, b2 = 0; n1 < t1.length; n1++) {
				while (b2 < t2.length && t2[b2].max < t1[n1].min)
					b2++;
				int min1 = t1[n1].min, max1 = t1[n1].max;
				for (int n2 = b2; n2 < t2.length && t1[n1].max >= t2[n2].min; n2++) {
					if (t2[n2].min > min1)
						return false;
					if (t2[n2].max < Integer.MAX_VALUE) 
						min1 = t2[n2].max + 1;
					else {
						min1 = Integer.MAX_VALUE;
						max1 = Integer.MIN_VALUE;
					}
					StatePair q = new StatePair(t1[n1].to, t2[n2].to);
					if (!visited.contains(q)) {
						worklist.add(q);
						visited.add(q);
					}
				}
				if (min1 <= max1)
					return false;
			}		
		}
		return true;
	}
	
	/**
	 * Returns an automaton that accepts the union of the languages of the given automata.
	 * <p>
	 * Complexity: linear in number of states.
	 */
	public static Automaton union(Automaton a1, Automaton a2) {
		if ((a1.isSingleton() && a2.isSingleton() && a1.singleton.equals(a2.singleton)) || a1 == a2)
			return a1.cloneIfRequired();
		a1 = a1.cloneExpandedIfRequired();
		a2 = a2.cloneExpandedIfRequired();
		State s = new State();
		s.addEpsilon(a1.initial);
		s.addEpsilon(a2.initial);
		a1.initial = s;
		a1.deterministic = false;
		a1.clearHashCode();
		a1.checkMinimizeAlways();
		return a1;
	}
	
	/**
	 * Returns an automaton that accepts the union of the languages of the given automata.
	 * <p>
	 * Complexity: linear in number of states.
	 */
	public static Automaton union(Collection<Automaton> l) {
		Set<Integer> ids = new HashSet<Integer>();
		for (Automaton a : l)
			ids.add(System.identityHashCode(a));
		boolean has_aliases = ids.size() != l.size();
		State s = new State();
		for (Automaton b : l) {
			if (b.isEmpty())
				continue;
			Automaton bb = b;
			if (has_aliases)
				bb = bb.cloneExpanded();
			else
				bb = bb.cloneExpandedIfRequired();
			s.addEpsilon(bb.initial);
		}
		Automaton a = new Automaton();
		a.initial = s;
		a.deterministic = false;
		a.clearHashCode();
		a.checkMinimizeAlways();
		return a;
	}

	/**
	 * Determinizes the given automaton using the given set of initial states. XXX: with the assumption that the alphabet is big
	 */
	public static void determinize_large_alphabet(Automaton a, AutomataObserver ao) {
		a.unreduce();

		Set<State> initialset = new HashSet<State>();
		initialset.add(a.getInitialState());

		// subset construction
		LinkedList<Set<State>> worklist = new LinkedList<Set<State>>();
		Map<Set<State>, State> newstate = new HashMap<Set<State>, State>();
		worklist.add(initialset);
		a.initial = new State();
		newstate.put(initialset, a.initial);

		while (worklist.size() > 0) {
			Set<State> s = worklist.removeFirst();
			State r = newstate.get(s);

			Map<Integer, Set<State>> newtrans = new HashMap<>();

			for (State q : s) {
				if (q.accept)
					r.accept = true;

				for (Transition t : q.transitions)
					newtrans.computeIfAbsent(t.min, (c) -> new HashSet<>()).add(t.to);
			}

			for (Entry<Integer, Set<State>> tt : newtrans.entrySet()) {
				int c = tt.getKey();
				Set<State> p = tt.getValue();
				State q = newstate.get(p);
				if (q == null) {
					worklist.add(p);
					newstate.put(p, q = new State());
				}
				r.transitions.add(new Transition(c, c, q));
			}
		}

		a.deterministic = true;
		a.removeDeadTransitions();

		Map<State, Set<State>> m = newstate.entrySet()
				.stream()
				.collect(Collectors.toMap(Map.Entry::getValue, Map.Entry::getKey));
		m.keySet().retainAll(a.getStates());
		ao.merged(m);
	}

	/**
	 * Determinizes the given automaton.
	 * <p>
	 * Complexity: exponential in number of states.
	 */
	public static void determinize(Automaton a) {
		if (a.deterministic || a.isSingleton())
			return;
		Set<State> initialset = new HashSet<State>();
		initialset.add(a.initial);
		determinize(a, initialset);
	}

	/** 
	 * Determinizes the given automaton using the given set of initial states. 
	 */
	static void determinize(Automaton a, Set<State> initialset) {
		int[] points = a.getStartPoints();
		// subset construction
		LinkedList<Set<State>> worklist = new LinkedList<Set<State>>();
		Map<Set<State>, State> newstate = new HashMap<Set<State>, State>();
		worklist.add(initialset);
		a.initial = new State();
		newstate.put(initialset, a.initial);
		while (worklist.size() > 0) {
			Set<State> s = worklist.removeFirst();
			State r = newstate.get(s);
			for (State q : s)
				if (q.accept) {
					r.accept = true;
					break;
				}
			for (int n = 0; n < points.length; n++) {
				Set<State> p = new HashSet<State>();
				for (State q : s)
					for (Transition t : q.transitions)
						if (t.min <= points[n] && points[n] <= t.max)
							p.add(t.to);
				if (!p.isEmpty()) {
                    State q = newstate.get(p);
                    if (q == null) {
                        worklist.add(p);
                        q = new State();
                        newstate.put(p, q);
                    }
                    int min = points[n];
                    int max;
                    if (n + 1 < points.length)
                        max = (int) (points[n + 1] - 1);
                    else
                        max = Integer.MAX_VALUE;
                    r.transitions.add(new Transition(min, max, q));
                }
			}
		}
		a.deterministic = true;
		a.removeDeadTransitions();
	}
	
	/**
	  * Determinizes the given automaton using the given set of initial states.
	  * 
	  * this version should be better for automata with a large alphabet
	  */
	static void determinize(Automaton a, Set<State> initialset, AutomataObserver i) {
		a.unreduce();

		// subset construction
		LinkedList<Set<State>> worklist = new LinkedList<Set<State>>();
		Map<Set<State>, State> newstate = new HashMap<Set<State>, State>();
		worklist.add(initialset);
		a.initial = new State();
		newstate.put(initialset, a.initial);
		while (worklist.size() > 0) {
			Set<State> s = worklist.removeFirst();
			State r = newstate.get(s);
			Map<Integer, Set<State>> newtrans = new HashMap<>();

			for (State q : s) {
				if (q.accept)
					r.accept = true;

				for (Transition t : q.transitions)
					newtrans.computeIfAbsent(t.min, (c) -> new HashSet<>()).add(t.to);
			}

			for (Entry<Integer, Set<State>> e : newtrans.entrySet()) {
				int c = e.getKey();
				Set<State> p = e.getValue();
				State q = newstate.get(p);
				if (q == null) {
					q = new State();
					newstate.put(p, q);
					worklist.add(p);
				}
				r.transitions.add(new Transition(c, c, q));
			}
		}
		a.deterministic = true;
		a.removeDeadTransitions();
		Map<State, Set<State>> m = newstate.entrySet()
				.stream()
				.collect(Collectors.toMap(Map.Entry::getValue, Map.Entry::getKey));
		m.keySet().retainAll(a.getStates());
		i.merged(m);
	}

	
	/** 
	 * Adds epsilon transitions to the given automaton.
	 * This method adds extra character interval transitions that are equivalent to the given
	 * set of epsilon transitions. 
	 * @param pairs collection of {@link StatePair} objects representing pairs of source/destination states 
	 *        where epsilon transitions should be added
	 */
	public static void addEpsilons(Automaton a, Collection<StatePair> pairs) {
		a.expandSingleton();
		HashMap<State, HashSet<State>> forward = new HashMap<State, HashSet<State>>();
		HashMap<State, HashSet<State>> back = new HashMap<State, HashSet<State>>();
		for (StatePair p : pairs) {
			HashSet<State> to = forward.get(p.s1);
			if (to == null) {
				to = new HashSet<State>();
				forward.put(p.s1, to);
			}
			to.add(p.s2);
			HashSet<State> from = back.get(p.s2);
			if (from == null) {
				from = new HashSet<State>();
				back.put(p.s2, from);
			}
			from.add(p.s1);
		}
		// calculate epsilon closure
		LinkedList<StatePair> worklist = new LinkedList<StatePair>(pairs);
		HashSet<StatePair> workset = new HashSet<StatePair>(pairs);
		while (!worklist.isEmpty()) {
			StatePair p = worklist.removeFirst();
			workset.remove(p);
			HashSet<State> to = forward.get(p.s2);
			HashSet<State> from = back.get(p.s1);
			if (to != null) {
				for (State s : to) {
					StatePair pp = new StatePair(p.s1, s);
					if (!pairs.contains(pp)) {
						pairs.add(pp);
						forward.get(p.s1).add(s);
						back.get(s).add(p.s1);
						worklist.add(pp);
						workset.add(pp);
						if (from != null) {
							for (State q : from) {
								StatePair qq = new StatePair(q, p.s1);
								if (!workset.contains(qq)) {
									worklist.add(qq);
									workset.add(qq);
								}
							}
						}
					}
				}
			}
		}
		// add transitions
		for (StatePair p : pairs)
			p.s1.addEpsilon(p.s2);
		a.deterministic = false;
		a.clearHashCode();
		a.checkMinimizeAlways();
	}

	/**
	 * This method a combination of operations to save memory.
	 */
	public static void addEpsilonsAndRemoveDeadTransitions(Automaton a, Collection<StatePair> eps,
			AutomataObserver ao) {
		a.expandSingleton();

		State initial = a.getInitialState();

		HashSet<State> allStates = new HashSet<State>();

		HashMap<State, Set<State>> forward = new HashMap<>();
		HashMap<State, Set<State>> back = new HashMap<>();
		for (StatePair p : eps) {
			back.computeIfAbsent(p.s2, s -> new HashSet<>()).add(p.s1);
			forward.computeIfAbsent(p.s1, s -> new HashSet<>()).add(p.s2);
		}

		{ // collect allStates and fill liveStates with reachable accepting states
			HashSet<State> liveStates = new HashSet<State>();

			Set<State> front = new HashSet<State>();
			front.add(initial);
			while (!front.isEmpty()) {
				allStates.addAll(front);
				Set<State> newfront = new HashSet<State>();
				for (State s0 : front) {
					if (s0.accept)
						liveStates.add(s0);

					for (Transition t : s0.transitions) {
						newfront.add(t.to);
						// compute back map for liveness computation next
						back.computeIfAbsent(t.to, s -> new HashSet<>()).add(s0);
					}
					newfront.addAll(forward.getOrDefault(s0, Collections.emptySet()));
				}
				newfront.removeAll(allStates);
				front = newfront;
			}

			// now walk backwards from current accepting liveStates to compute all liveStates
			front.clear();
			front.addAll(liveStates);
			while (!front.isEmpty()) {
				liveStates.addAll(front);
				Set<State> newfront = new HashSet<State>();
				for (State s1 : front)
					newfront.addAll(back.getOrDefault(s1, Collections.emptySet()));
				newfront.removeAll(liveStates);
				front = newfront;
			}

			// finally.. remove transitions to (and from) deadstates
			eps.removeIf(p -> !(liveStates.contains(p.s1) && liveStates.contains(p.s2)));
			for (State s : liveStates)
				s.transitions.removeIf(t -> !liveStates.contains(t.to));
			allStates.retainAll(liveStates);
		}

		// recompute front and back
		forward.clear();
		back.clear();
		for (StatePair p : eps) {
			forward.computeIfAbsent(p.s1, s -> new HashSet<>()).add(p.s2);
			back.computeIfAbsent(p.s2, s -> new HashSet<>()).add(p.s1);
		}

		{// compute eps = transitive_closure (eps)
			LinkedList<StatePair> worklist = new LinkedList<StatePair>(eps);
			HashSet<StatePair> workset = new HashSet<StatePair>(eps);
			while (!worklist.isEmpty()) {
				StatePair p = worklist.removeFirst();
				workset.remove(p);
				Set<State> to = forward.get(p.s2);
				Set<State> from = back.get(p.s1);
				if (to != null) {
					for (State s : to) {
						StatePair pp = new StatePair(p.s1, s);
						if (!eps.contains(pp)) {
							eps.add(pp);
							forward.get(p.s1).add(s);
							back.get(s).add(p.s1);
							worklist.add(pp);
							workset.add(pp);
							if (from != null) {
								for (State q : from) {
									StatePair qq = new StatePair(q, p.s1);
									if (!workset.contains(qq)) {
										worklist.add(qq);
										workset.add(qq);
									}
								}
							}
						}
					}
				}
			}
		} // eps is now transitively closed

		HashMap<State, Set<State>> merge_info = new HashMap<>();
		for (State s : allStates)
			merge_info.put(s, new HashSet<>(Collections.singleton(s)));

		// dead states were removed from eps already
		// forward.keySet().retainAll(allStates)
		for (Entry<State, Set<State>> e : forward.entrySet()) {
			State s0 = e.getKey();
			for (State s1 : e.getValue())
				s0.addEpsilon(s1);
			merge_info.get(s0).addAll(e.getValue());
		}

		/*
		 * // add transitions for (StatePair p : eps) { p.s1.addEpsilon(p.s2);
		 * 
		 * if (!p.s2.transitions.isEmpty() || p.s2.isAccept()) merge_info.get(p.s1).add(p.s2); }
		 */
		a.deterministic = false;
		a.clearHashCode();

		// only states are eliminated because they're no longer reachable.. now new states should be rendered "dead"
		merge_info.keySet().retainAll(a.getStates());

		ao.merged(merge_info);

		// don't minimize.. a.checkMinimizeAlways();
	}

	/**
	 * Returns true if the given automaton accepts the empty string and nothing else.
	 */
	public static boolean isEmptyString(Automaton a) {
		if (a.isSingleton())
			return a.singleton.length() == 0;
		else
			return a.initial.accept && a.initial.transitions.isEmpty();
	}

	/**
	 * Returns true if the given automaton accepts no strings.
	 */
	public static boolean isEmpty(Automaton a) {
		if (a.isSingleton())
			return false;
		return !a.initial.accept && a.initial.transitions.isEmpty();
	}
	
	/**
	 * Returns true if the given automaton accepts all strings.
	 */
	public static boolean isTotal(Automaton a) {
		if (a.isSingleton())
			return false;
		if (a.initial.accept && a.initial.transitions.size() == 1) {
			Transition t = a.initial.transitions.iterator().next();
			return t.to == a.initial && t.min == Integer.MIN_VALUE && t.max == Integer.MAX_VALUE;
		}
		return false;
	}
	
	/**
	 * Returns a shortest accepted/rejected string. 
	 * If more than one shortest string is found, the lexicographically first of the shortest strings is returned.
	 * @param accepted if true, look for accepted strings; otherwise, look for rejected strings
	 * @return the string, null if none found
	 */
	public static String getShortestExample(Automaton a, boolean accepted) {
		if (a.isSingleton()) {
			if (accepted)
				return a.singleton;
			else if (a.singleton.length() > 0)
				return "";
			else
				return "\u0000";

		}
		return getShortestExample(a.getInitialState(), accepted);
	}

	static String getShortestExample(State s, boolean accepted) {
		Map<State,String> path = new HashMap<State,String>();
		LinkedList<State> queue = new LinkedList<State>();
		path.put(s, "");
		queue.add(s);
		String best = null;
		while (!queue.isEmpty()) {
			State q = queue.removeFirst();
			String p = path.get(q);
			if (q.accept == accepted) {
				if (best == null || p.length() < best.length() || (p.length() == best.length() && p.compareTo(best) < 0))
					best = p;
			} else 
				for (Transition t : q.getTransitions()) {
					String tp = path.get(t.to);
					String np = p + t.min;
					if (tp == null || (tp.length() == np.length() && np.compareTo(tp) < 0)) {
						if (tp == null)
							queue.addLast(t.to);
						path.put(t.to, np);
					}
				}
		}
		return best;
	}
	
	/**
	 * Returns true if the given string is accepted by the automaton. 
	 * <p>
	 * Complexity: linear in the length of the string.
	 * <p>
	 * <b>Note:</b> for full performance, use the {@link RunAutomaton} class.
	 */
	public static boolean run(Automaton a, String s) {
		if (a.isSingleton())
			return s.equals(a.singleton);
		if (a.deterministic) {
			State p = a.initial;
			for (int i = 0; i < s.length(); i++) {
				State q = p.step(s.charAt(i));
				if (q == null)
					return false;
				p = q;
			}
			return p.accept;
		} else {
			Set<State> states = a.getStates();
			Automaton.setStateNumbers(states);
			LinkedList<State> pp = new LinkedList<State>();
			LinkedList<State> pp_other = new LinkedList<State>();
			BitSet bb = new BitSet(states.size());
			BitSet bb_other = new BitSet(states.size());
			pp.add(a.initial);
			ArrayList<State> dest = new ArrayList<State>();
			boolean accept = a.initial.accept;
			for (int i = 0; i < s.length(); i++) {
				int c = s.charAt(i);
				accept = false;
				pp_other.clear();
				bb_other.clear();
				for (State p : pp) {
					dest.clear();
					p.step(c, dest);
					for (State q : dest) {
						if (q.accept)
							accept = true;
						if (!bb_other.get(q.number)) {
							bb_other.set(q.number);
							pp_other.add(q);
						}
					}
				}
				LinkedList<State> tp = pp;
				pp = pp_other;
				pp_other = tp;
				BitSet tb = bb;
				bb = bb_other;
				bb_other = tb;
			}
			return accept;
		}
	}
}
