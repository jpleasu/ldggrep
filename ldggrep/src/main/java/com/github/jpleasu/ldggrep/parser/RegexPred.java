package com.github.jpleasu.ldggrep.parser;

public class RegexPred extends Predicate {
	public final String re;

	public RegexPred(String re) {
		this.re = re;
	}

	public String toString() {
		return String.format("Regex(%s)", re);
	}
}
