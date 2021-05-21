package com.github.jpleasu.ldggrep.java;

public class RefLink extends Link<MethodNode, Node> {

	public RefLink(MethodNode d0, Node d1) {
		super(d0, d1);
	}

	@Override
	public String toString() {
		return "refers to";
	}
}
