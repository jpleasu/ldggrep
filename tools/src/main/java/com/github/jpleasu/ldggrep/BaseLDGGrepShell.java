package com.github.jpleasu.ldggrep;

import java.io.Console;
import java.util.*;
import java.util.Map.Entry;
import java.util.stream.Collectors;

import com.github.jpleasu.ldggrep.graphing.Util;
import com.github.jpleasu.ldggrep.parser.Expr;
import com.github.jpleasu.ldggrep.parser_generated.ParseException;

/**
 *
 * Base class for LDGGrep shells
 * 
 * @param <N> the node type
 * @param <E> the edge type
 */
abstract public class BaseLDGGrepShell<N, E> {

	protected LDGModel<N, E> newModel() {
		return new LDGModel<N, E>();
	}

	abstract protected LDG<N, E> newLDG();

	protected LDGMatcher<N, E> newMatcher(LDGModel<N, E> model, Expr expr) {
		return new LDGMatcher<N, E>(model, expr);
	}

	protected void startREPL() {
		Console con = System.console();

		Map<Integer, Set<N>> currentMemory = new HashMap<>();
		final LDGModel<N, E> model = newModel();

		final LDG<N, E> graph = newLDG();

		con.printf("%s\n---\n", this.getClass().getSimpleName());
		con.printf("  Type \"?\" for help\n");
		boolean minmatch = false;
		try {
			while (true) {
				// XXX handle multiline?
				String entry = con.readLine("> ");
				if (entry == null)
					return;
				entry = entry.trim();
				if (entry.equals("quit"))
					return;
				if (entry.isEmpty()) {
					continue;
				}
				else if (entry.equals("?")) {
					con.printf("Commands:\n");
					con.printf("  ?    - this help message\n");
					con.printf("  ?i   - dump currently stored information, from sto(#)\n");
					con.printf("  ?m   - toggle minimal matching\n");
					con.printf("  ?p   - dump available predicates\n");
					con.printf("  quit - to exit\n");
					con.printf("\n");
				}
				else if (entry.equals("?p")) {
					con.printf("Node predicates:\n");
					MethodManager methodManager = model.getMethodManager();
					methodManager.forEachPred(NPred.class, (proto, desc) -> {
						con.printf("  %s - %s\n", proto, desc);
					});
					con.printf("Edge predicates:\n");
					methodManager.forEachPred(EPred.class, (proto, desc) -> {
						con.printf("  %s - %s\n", proto, desc);
					});

				}
				else if (entry.equals("?i")) {
					con.printf("Memory:\n");
					for (Entry<Integer, Set<N>> e : currentMemory.entrySet()) {
						List<String> nodes = e.getValue()
								.stream()
								.map(n -> n.toString())
								.sorted()
								.collect(Collectors.toList());
						con.printf("  <mem(%d)>: %d nodes\n", e.getKey(), nodes.size());
						for (String ns : nodes)
							con.printf("    %s\n", ns);
					}
				}
				else if (entry.equals("?m")) {
					minmatch = !minmatch;
					con.printf("Minmatch only: %s\n", minmatch ? "on" : "off");
				}
				else {
					con.printf("searching...\n");
					entry = entry.trim();
					try {

						List<Expr> exprList = Expr.parseList(entry);

						LDGMatch<N, E> match = null;
						int cnt = 1;
						for (Expr expr : exprList) {
							long m0 = System.currentTimeMillis();
							LDGMatcher<N, E> matcher = newMatcher(model, expr);
							model.setIncomingMemory(currentMemory);
							if (minmatch)
								match = matcher.minmatch(graph);
							else
								match = matcher.match(graph);
							long m1 = System.currentTimeMillis();
							con.printf("  completed %d/%d in %f seconds\n", cnt++, exprList.size(),
								(double) (m1 - m0) / 1000);
						}

						if (match == null) {
							con.printf("no match\n");
						}
						else {
							currentMemory.putAll(match.memory);
							if (!entry.endsWith(";")) {
								con.printf("displaying in graph window...\n");
								Util.showJungrapht(model, match, entry);
							}
						}
					}
					catch (ParseException e) {
						e.printStackTrace();
					}
					catch (RuntimeException e) {
						if (e.getCause() instanceof ParseException) {
							e.getCause().printStackTrace();
						}
						else {
							throw e;
						}
					}
				}
			}
		}
		finally {
			// XXX close graph window
			con.printf("\n\n");
		}
	}
}
