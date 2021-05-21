package com.github.jpleasu.ldggrep.java;

public class ImplementsInterfaceLink extends Link<ClassNode, ClassNode> {

	public ImplementsInterfaceLink(ClassNode d0, ClassNode d1) {
		super(d0, d1);
	}

	@Override
	public String toString() {
		// return String.format("%s implements %s", src.name, dst.name);
		return "implements";
	}
}
