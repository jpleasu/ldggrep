package com.github.jpleasu.ldggrep.file;

import com.github.jpleasu.ldggrep.LDGMatcher;
import com.github.jpleasu.ldggrep.LDGModel;
import com.github.jpleasu.ldggrep.parser.Expr;

public class GraphFileMatcher extends LDGMatcher<Node, Edge> {

	public GraphFileMatcher(LDGModel<Node, Edge> model, Expr e) {
		super(model, e);
	}

	public GraphFileMatcher(LDGModel<Node, Edge> model, String pat) {
		this(model, Expr.parse(pat));
	}
}