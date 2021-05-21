package com.github.jpleasu.ldggrep.internal;

public class NTrans<N> extends Trans {
	public final Pred<N> p;

	public NTrans(Pred<N> p, int target) {
		super(target);
		this.p = p;
	}

	@Override
	public String toString() {
		return String.format("N(%s)", p);
	}
}