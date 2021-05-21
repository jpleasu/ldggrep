package com.github.jpleasu.ldggrep.internal;

public interface Pred<X> {
	/**
	 * 
	 * at position i in the expression, does the node/edge x match? 
	 * 
	 * @param i position in match 
	 * @param x a node or edge
	 * @return true if there is a match at the given position
	 */
	boolean matches(int i, X x);
}