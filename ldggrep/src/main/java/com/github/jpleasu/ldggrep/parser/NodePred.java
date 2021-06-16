package com.github.jpleasu.ldggrep.parser;

public class NodePred extends Pat {
	public final Predicate p;

	public NodePred(Predicate p) {
		this.p = p;
	}

	public String toString() {
		return String.format("Node(%s)", p);
	}
}
