package com.github.jpleasu.ldggrep.rest;

import java.io.IOException;
import java.io.InputStreamReader;
import java.util.*;
import java.util.Map.Entry;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import com.github.jpleasu.ldggrep.*;
import com.github.jpleasu.ldggrep.graphing.Util;
import com.github.jpleasu.ldggrep.parser.Expr;
import com.github.jpleasu.ldggrep.parser_generated.ParseException;
import com.github.jpleasu.ldggrep.parser_generated.Parser;
import com.github.jpleasu.ldggrep.util.JsonProxy;
import com.github.jpleasu.ldggrep.util.Pair;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.annotations.Expose;

import dk.brics.automaton.State;
import dk.brics.automaton.Transition;
import jakarta.servlet.ServletConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.*;

public class RestGrepServlet extends HttpServlet {
	private static final long serialVersionUID = -2395355126945543589L;

	Gson gson =
		new GsonBuilder().setPrettyPrinting().excludeFieldsWithoutExposeAnnotation().create();

	Boolean showmatch;

	@Override
	public void init(ServletConfig config) throws ServletException {
		super.init(config);
		showmatch = Boolean.valueOf(config.getInitParameter("showmatch"));
	}

	Graph match2graph(LDGMatch<Node, Edge> m) {
		Graph g = new Graph();

		for (Entry<State, Set<Pair<Integer, Node>>> s_ent : m.s2ps.entrySet()) {
			Node v = new Node();
			State s = s_ent.getKey();
			v.id = s.toString();
			// props= [ [int,vert], [int,vert], ...]
			v.props = gson.toJsonTree(s_ent.getValue()
					.stream()
					.map(k -> List.of(k.getLeft(), k.getRight()))
					.collect(Collectors.toList()));
			g.nodes.add(v);

			for (Transition t : s.getTransitions()) {
				for (int c = t.getMin(); c <= t.getMax(); ++c) {
					Edge l = m.c2e.get(c);
					Edge e = new Edge();
					e.id = String.format("Trans%d", g.edges.size());
					e.srcid = s.toString();
					e.dstid = t.getDest().toString();
					e.props = l.props;
					g.edges.add(e);
				}
			}
		}
		return g;
	}

	static class Matcher extends LDGMatcher<Node, Edge> {

		public Matcher(Model model, Expr e) {
			super(model, e);
		}

		public Matcher(Model model, String pat) {
			super(model, pat);
		}
	}

	class Model extends LDGModel<Node, Edge> {
		Model() {
			initializeCodeContext();
		}

		@Override
		protected Object nodeToCodeObject(Node n) {
			return JsonProxy.of(n.props);
		}

		@Override
		protected Object edgeToCodeObject(Edge e) {
			return JsonProxy.of(e.props);
		}

		@Override
		public String nodeToString(Node n) {
			return gson.toJson(n.props);
		}

		@Override
		public String edgeToString(Edge e) {
			return gson.toJson(e.props);
		}

	}

	static class RestLDG implements LDG<Node, Edge> {
		final Graph g;

		RestLDG(Graph g) {
			this.g = g;
			g.wire();
		}

		@Override
		public Stream<Node> startNodes() {
			return g.nodes.parallelStream();
		}

		@Override
		public Stream<Edge> outEdges(Node n) {
			return n.outedges.stream();
		}

		@Override
		public Node targetNode(Edge e) {
			return e.dst;
		}

	}

	void send(HttpServletResponse resp, Object o) throws IOException {
		resp.setContentType("application/json");
		resp.setStatus(HttpServletResponse.SC_OK);
		resp.getWriter().println(gson.toJson(o));
	}

	HttpServletResponse currentResponse;

	private Model model = new Model();

	private Graph current_graph;

	private RestLDG current_ldg;

	Map<Integer, Set<Node>> current_memory = new HashMap<>();

	static class Query {
		@Expose
		String query;
		boolean minimum = false;
	}

	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse resp)
			throws ServletException, IOException {
		System.err.printf("GET %s\n", req.getPathInfo());
	}

	@Override
	protected void doPost(HttpServletRequest req, HttpServletResponse resp)
			throws ServletException, IOException {
		try {
			String p = req.getPathInfo();
			System.err.printf("POST %s\n", p);
			if (p.equals("/setGraph")) {
				// JsonObject o = gson.fromJson(new InputStreamReader(req.getInputStream()), JsonObject.class);
				Graph g = gson.fromJson(new InputStreamReader(req.getInputStream()), Graph.class);
				g.wire();
				current_graph = g;
				current_ldg = new RestLDG(current_graph);
				current_memory.clear();
				send(resp, "ok");
			}
			else if (p.equals("/query")) {
				Query q = gson.fromJson(new InputStreamReader(req.getInputStream()), Query.class);

				Parser p1 = new Parser(q.query);
				LDGMatch<Node, Edge> tmp_match = null;
				try {
					List<Expr> el = p1.expr_list();

					int cnt = 1;
					for (Expr e : el) {
						long m0 = System.currentTimeMillis();
						Matcher matcher = new Matcher(model, e);
						model.setIncomingMemory(current_memory);
						tmp_match = matcher.match(current_ldg);
						if (tmp_match == null)
							break;
						current_memory.putAll(tmp_match.memory);
						long m1 = System.currentTimeMillis();
						System.err.printf("  completed %d/%d in %f seconds\n", cnt++, el.size(),
							(double) (m1 - m0) / 1000);
					}
				}
				catch (ParseException err) {
					err.printStackTrace();
				}

				LDGMatch<Node, Edge> match = tmp_match;
				if (match == null) {
					send(resp, "no match");
				}
				else {
					if (showmatch) {
						new Thread(() -> Util.showJungrapht(model, match, q.query)).start();
					}
					send(resp, match2graph(match));
				}
			}
			else {
				resp.sendError(HttpServletResponse.SC_BAD_REQUEST, "you bad");
			}
		}
		catch (Throwable t) {
			t.printStackTrace(System.err);
			resp.sendError(HttpServletResponse.SC_BAD_REQUEST, t.getMessage());
		}
	}
}
