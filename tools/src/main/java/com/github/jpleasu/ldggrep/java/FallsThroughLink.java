package com.github.jpleasu.ldggrep.java;

/**
 *
 * when a class doesn't have a method, but its parent does
 * 
 */
public class FallsThroughLink extends Link<MethodNode, MethodNode> {

	public FallsThroughLink(MethodNode d0, MethodNode d1) {
		super(d0, d1);
	}

	@Override
	public String toString() {
		return "falls through to";
	}
}
