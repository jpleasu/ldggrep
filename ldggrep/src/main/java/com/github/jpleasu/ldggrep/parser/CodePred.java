package com.github.jpleasu.ldggrep.parser;

public class CodePred extends Predicate {
	public final String code;

	public CodePred(String code) {
		this.code = code;
	}

	public String toString() {
		return String.format("Code(%s)", code);
	}
}
