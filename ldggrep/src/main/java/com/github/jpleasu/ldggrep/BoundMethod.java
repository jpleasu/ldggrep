package com.github.jpleasu.ldggrep;

import java.lang.reflect.Method;

import com.github.jpleasu.ldggrep.internal.MethodInfo;

/**
 * a Java Method bound to an object with additional info
 */
public class BoundMethod {
	public final Object obj;
	public final Method method;
	public final MethodInfo info;

	public BoundMethod(Object obj, Method method, MethodInfo info) {
		this.obj = obj;
		this.method = method;
		this.info = info;
	}

}