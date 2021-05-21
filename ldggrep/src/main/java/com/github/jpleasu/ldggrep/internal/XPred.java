package com.github.jpleasu.ldggrep.internal;

import java.lang.annotation.Annotation;
import java.lang.reflect.Method;

import com.github.jpleasu.ldggrep.EPred;
import com.github.jpleasu.ldggrep.NPred;

/**
 * There is no inheritance for annotations, so use reflection.  
 */
public class XPred {
	private final String name;
	public final String description;
	public final String[] args;

	public XPred(Class<? extends Annotation> annClass, Method method) {
		this(method.getAnnotation(annClass));
	}

	public XPred(Annotation ann) {
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
