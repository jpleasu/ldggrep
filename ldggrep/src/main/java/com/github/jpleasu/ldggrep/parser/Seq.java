package com.github.jpleasu.ldggrep.parser;

import java.util.ArrayList;
import java.util.List;

public class Seq extends Pat {
	public final List<Pat> l = new ArrayList<Pat>();

	public int size() {
		return l.size();
	}

	public void add(Pat p) {
		l.add(p);
	}

	public String toString() {
		return String.format("Seq(%s)", catPats(",", l));
	}
}
