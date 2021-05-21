package com.github.jpleasu.ldggrep.java;

public class DefinesMethodLink extends Link<ClassNode, MethodNode> {

	public DefinesMethodLink(ClassNode d0, MethodNode d1) {
		super(d0, d1);
	}

	@Override
	public String toString() {
		return "defines";
	}

}
