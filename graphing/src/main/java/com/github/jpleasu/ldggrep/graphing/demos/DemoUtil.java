package com.github.jpleasu.ldggrep.graphing.demos;

import java.util.function.Function;
import java.util.function.Supplier;

public class DemoUtil {
	static class StringSupplier implements Supplier<String> {
		int n = 0;

		final String base;

		StringSupplier(String base) {
			this.base = base;
		}

		@Override
		public String get() {
			return gen(base, n++);
		}

		public Supplier<String> andThen(Function<String, String> a) {
			return () -> a.apply(this.get());
		}
	}

	static String gen(String idx, int n) {
		String s = "";
		do {
			int r = n % idx.length();
			s += idx.charAt(r);
			n /= idx.length();
		}
		while (n > 0);

		return s;
	}

}
