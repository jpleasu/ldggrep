package com.github.jpleasu.ldggrep.parser;

public class Rep extends Pat {
	public final Pat p;
	public final int a;
	public final int b;

	public Rep(Pat p, int a, int b) {
		this.p = p;
		this.a = a;
		this.b = b;
	}

	public String toString() {
		return String.format("Rep(%s,%d,%d)", p.toString(), a, b);
	}
}
