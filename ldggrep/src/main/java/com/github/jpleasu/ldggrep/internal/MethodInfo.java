package com.github.jpleasu.ldggrep.internal;

import java.lang.annotation.Annotation;

import com.github.jpleasu.ldggrep.*;

/**
 * method information parsed from an LDGGrep annotation  
 */
public class MethodInfo {
	private final String name;
	public final String description;
	public final String[] args;

	public MethodInfo(String name, String[] args, String description) {
		this.name = name;
		this.args = args;
		this.description = description;
	}

	public MethodInfo(Annotation ann) {
		if (ann instanceof NPred) {
			this.name = ((NPred) ann).value();
			this.args = ((NPred) ann).args();
			this.description = ((NPred) ann).description();
		}
		else if (ann instanceof EPred) {
			this.name = ((EPred) ann).value();
			this.args = ((EPred) ann).args();
			this.description = ((EPred) ann).description();
		}
		else {
			throw new RuntimeException(
				"type is not an EPred or NPred: " + ann.getClass().getName());
		}
	}

	public String getName(String def) {
		if (name.isEmpty()) {
			return def;
		}
		return name;
	}
}
