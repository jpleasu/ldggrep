package com.github.jpleasu.ldggrep.parser;

public class NotPred extends Predicate {
	public final Predicate p;

	public NotPred(Predicate p) {
		this.p = p;
	}

	public String toString() {
		return String.format("Not(%s)", p);
	}
}
