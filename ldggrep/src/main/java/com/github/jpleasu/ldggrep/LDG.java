package com.github.jpleasu.ldggrep;

import java.util.stream.Stream;

/**
 * 
 * what an LDGMatcher matches against -- a labeled directed graph
 *
 * @param <N> the node type
 * @param <E> the edge type
 */
public interface LDG<N, E> {

	/**
	 * @return a stream of nodes that all queries will start with
	 */
	Stream<N> startNodes();

	/**
	 * @param n a node from this model
	 * @return a stream of edges leaving {@code n}
	 */
	Stream<E> outEdges(N n);

	/**
	 * 
	 * @param e an edge from this model
	 * @return the target node of {@code e}
	 */
	N targetNode(E e);
}
