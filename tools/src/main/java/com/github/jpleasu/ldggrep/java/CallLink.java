package com.github.jpleasu.ldggrep.java;

public class CallLink extends Link<MethodNode, MethodNode> {

	public CallLink(MethodNode d0, MethodNode d1) {
		super(d0, d1);
	}

	@Override
	public String toString() {
		return "calls";
	}

}
