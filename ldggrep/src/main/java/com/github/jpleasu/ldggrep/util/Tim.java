package com.github.jpleasu.ldggrep.util;

public class Tim {
	long t = -1;
	String what = null;

	long memUsed() {
		return Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory();
	}

	public void mark(String newwhat) {
		long t0 = t;
		t = System.currentTimeMillis();
		if (t0 != -1) {
			System.err.printf("timed %s %d milliseconds, %d used\n", this.what, t - t0, memUsed());
		}
		this.what = newwhat;
	}
}
