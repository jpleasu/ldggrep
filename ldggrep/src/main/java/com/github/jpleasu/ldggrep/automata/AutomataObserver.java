package com.github.jpleasu.ldggrep.automata;

import java.util.Map;
import java.util.Set;

import dk.brics.automaton.State;

/**
 * track information about an automaton through various operations, like determinization and minimization.
 * 
 */
public interface AutomataObserver {

	/**
	 * Called when states are merged.  The argument is the complete map from new to old states.
	 * 
	 * (only live states are accounted for)
	 * 
	 * m.get(new_state) = set of old states
	 * 
	 * @param m mapping from new states to corresponding (set of) old states
	 */
	void merged(Map<State, Set<State>> m);

}
