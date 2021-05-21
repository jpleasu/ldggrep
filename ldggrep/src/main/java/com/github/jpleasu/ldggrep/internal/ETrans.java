package com.github.jpleasu.ldggrep.internal;

public class ETrans<E> extends Trans {
	public final Pred<E> p;

	public ETrans(Pred<E> p, int target) {
		super(target);
		this.p = p;
	}

	@Override
	public String toString() {
		return String.format("E(%s)", p);
	}
}