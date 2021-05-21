package com.github.jpleasu.ldggrep.java;

public class ReturnLink extends Link<MethodNode, ClassNode> {

	public ReturnLink(MethodNode d0, ClassNode d1) {
		super(d0, d1);
	}

	@Override
	public String toString() {
		return "returns";
	}

}
