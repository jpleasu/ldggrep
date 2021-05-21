package com.github.jpleasu.ldggrep.java;

/**
 *
 * when a child implements a method of the parent.. e.g. if the "parent" is an interface
 *
 */
public class ImplementedByLink extends Link<MethodNode, MethodNode> {

	public ImplementedByLink(MethodNode d0, MethodNode d1) {
		super(d0, d1);
	}

	@Override
	public String toString() {
		return "implemented by";
	}
}
