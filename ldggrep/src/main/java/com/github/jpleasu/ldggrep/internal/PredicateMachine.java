package com.github.jpleasu.ldggrep.internal;

import java.util.*;

import com.github.jpleasu.ldggrep.LDGModel;
import com.github.jpleasu.ldggrep.parser.*;

/**
 * State machine representation of an LDGGrep query pattern
 *
 * @param <N> node type
 * @param <E> edge type
 */
public class PredicateMachine<N, E> {
	final public static int INITIAL_STATE = 0;
	final public static int FINAL_STATE = 1;

	final private LDGModel<N, E> model;
	final private HashMap<Integer, List<Trans>> outEdges = new HashMap<>();
	private int numStates = 0;

	public PredicateMachine(LDGModel<N, E> model, Expr queryExpression) {
		this.model = model;
		numStates = 2;
		addPatternTransition(0, queryExpression.p, 1);
	}

	private void addTransition(int n0, Trans e) {
		transitionsFrom(n0).add(e);
	}

	public Collection<Trans> transitionsFrom(int n) {
		return outEdges.computeIfAbsent(n, n_ -> new ArrayList<>());
	}

	private void addEpsilonTransition(int s0, int s1) {
		addTransition(s0, new Eps(s1));
	}

	private void addPatternTransition(int s0, Pat pat, int s1) {
		int i;
		Integer s;

		if (pat instanceof Alt) {
			Alt alt = (Alt) pat;
			for (Pat p : alt.l)
				addPatternTransition(s0, p, s1);
		}
		else if (pat instanceof Seq) {
			Seq seq = (Seq) pat;
			List<Pat> l = seq.l;
			s = s0;
			for (Pat p : l.subList(0, seq.l.size() - 1))
				addPatternTransition(s, p, s = numStates++);
			addPatternTransition(s, l.get(l.size() - 1), s1);
		}
		else if (pat instanceof Rep) {
			Rep rep = (Rep) pat;
			s = s0;
			// the minimal count
			for (i = 0; i < rep.a; ++i)
				addPatternTransition(s, rep.p, s = numStates++);

			// optional part
			if (rep.b != -1) {
				for (i = rep.a; i < rep.b; ++i) {
					addEpsilonTransition(s, s1);
					addPatternTransition(s, rep.p, s = numStates++);
				}
			}
			else
				addPatternTransition(s, rep.p, s);
			addEpsilonTransition(s, s1);
		}
		else if (pat instanceof Predicate) {
			Pred<E> p = model.buildEdgePred((Predicate) pat);
			addTransition(s0, new ETrans<>(p, s1));
		}
		else if (pat instanceof StatePred) {
			StatePred sp = (StatePred) pat;
			Pred<N> p = model.buildNodePred(sp.p);
			addTransition(s0, new NTrans<>(p, s1));
		}
	}

}