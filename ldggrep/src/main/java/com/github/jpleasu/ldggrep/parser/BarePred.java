package com.github.jpleasu.ldggrep.parser;

import java.util.Collections;
import java.util.List;

public class BarePred extends Predicate {
	public final String name;
	public final List<Object> args;

	public BarePred(String name, List<Object> args) {
		this.name = name;
		this.args = args != null ? args : Collections.emptyList();
	}

	public String toString() {
		if (args.isEmpty())
			return String.format("Bare(%s)", name);
		return String.format("Bare(%s,%s)", name, args);
	}
}
