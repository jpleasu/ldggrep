package com.github.jpleasu.ldggrep.parser;

import java.util.List;

public class Pat {
	static String catPats(String sep, List<Pat> l) {
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < l.size(); ++i) {
			sb.append(l.get(i).toString());
			sb.append(sep);
		}
		return sb.substring(0, sb.length() - 1);
	}
}
