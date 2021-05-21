package com.github.jpleasu.ldggrep.java;

public class ExtendsLink extends Link<ClassNode, ClassNode> {

	public ExtendsLink(ClassNode d0, ClassNode d1) {
		super(d0, d1);
	}

	@Override
	public String toString() {
		// return String.format("%s extends %s", src.name, dst.name);
		return "extends";
	}
}
