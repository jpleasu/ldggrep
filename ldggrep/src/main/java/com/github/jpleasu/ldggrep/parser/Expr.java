package com.github.jpleasu.ldggrep.parser;

import java.util.List;

import com.github.jpleasu.ldggrep.parser_generated.ParseException;
import com.github.jpleasu.ldggrep.parser_generated.Parser;

public class Expr extends Pat {
	public final Pat p;

	public Expr(Pat p) {
		this.p = p;
	}

	public String toString() {
		return String.format("Expr(%s)", p);
	}

	public static List<Expr> parseList(String pat) throws ParseException {
		return (new Parser(pat)).expr_list();
	}

	public static Expr parse(String pat) {
		try {
			Parser p = new Parser(pat);
			return p.expr();
		}
		catch (ParseException err) {
			err.printStackTrace();
		}
		return null;
	}
}
