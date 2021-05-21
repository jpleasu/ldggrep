package com.github.jpleasu.ldggrep.parser;

public class LiteralPred extends Predicate {
	public final String value;

	public LiteralPred(String value) {
		this.value = value;
	}

	public String toString() {
		return String.format("Literal(%s)", value);
	}
}
