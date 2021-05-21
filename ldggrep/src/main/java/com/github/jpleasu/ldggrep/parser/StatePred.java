package com.github.jpleasu.ldggrep.parser;

public class StatePred extends Pat {
	public final Predicate p;

	public StatePred(Predicate p) {
		this.p = p;
	}

	public String toString() {
		return String.format("State(%s)", p);
	}
}
