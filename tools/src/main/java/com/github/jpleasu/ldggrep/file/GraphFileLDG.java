package com.github.jpleasu.ldggrep.file;

import java.io.File;
import java.util.Map;
import java.util.Map.Entry;
import java.util.function.BiConsumer;
import java.util.stream.Stream;

import org.jgrapht.alg.util.Pair;
import org.jgrapht.graph.DirectedPseudograph;
import org.jgrapht.nio.*;
import org.jgrapht.nio.csv.CSVImporter;
import org.jgrapht.nio.dimacs.DIMACSImporter;
import org.jgrapht.nio.dot.DOTImporter;
import org.jgrapht.nio.gexf.SimpleGEXFImporter;
import org.jgrapht.nio.gml.GmlImporter;
import org.jgrapht.nio.graphml.GraphMLImporter;
import org.jgrapht.nio.json.JSONImporter;

import com.github.jpleasu.ldggrep.LDG;

public class GraphFileLDG implements LDG<Node, Edge> {
	// @formatter:off
	static Map<String, GraphImporter<Node, Edge>> importers = Map.of(
		".dot", new DOTImporter<>(),
		".graphml", new GraphMLImporter<>(),
		".csv", new CSVImporter<>(),
		".dimacs", new DIMACSImporter<>(),
		".gml", new GmlImporter<>(),
		".json", new JSONImporter<>(),
		".gexf", new SimpleGEXFImporter<>()
	);
	// @formatter:on

	static GraphImporter<Node, Edge> lookupImporter(String fname) {
		GraphImporter<Node, Edge> importer = null;
		for (Entry<String, GraphImporter<Node, Edge>> e : GraphFileLDG.importers.entrySet()) {
			if (fname.endsWith(e.getKey())) {
				importer = e.getValue();
				break;
			}
		}
		return importer;
	}

	final DirectedPseudograph<Node, Edge> g;

	public GraphFileLDG(String fname) {
		super();

		File f = new File(fname);

		g = new DirectedPseudograph<>(Node::new, Edge::new, false);

		GraphImporter<Node, Edge> importer = lookupImporter(fname);

		@SuppressWarnings({ "unchecked" })
		BaseEventDrivenImporter<Node, Edge> eventImporter =
			(BaseEventDrivenImporter<Node, Edge>) importer;

		eventImporter.addVertexAttributeConsumer(new BiConsumer<Pair<Node, String>, Attribute>() {
			@Override
			public void accept(Pair<Node, String> ns, Attribute a) {
				Node n = ns.getFirst();
				String s = ns.getSecond();
				if (s.equals(DOTImporter.DEFAULT_VERTEX_ID_KEY)) {
					n.name = a.getValue();
				}
			}
		});
		eventImporter.addEdgeAttributeConsumer(new BiConsumer<Pair<Edge, String>, Attribute>() {
			@Override
			public void accept(Pair<Edge, String> es, Attribute a) {
				Edge e = es.getFirst();
				String s = es.getSecond();
				if (s.equals("label")) {
					e.label = a.getValue();
				}
			}
		});

		importer.importGraph(g, f);
	}

	@Override
	public Stream<Edge> outEdges(Node n) {
		return g.outgoingEdgesOf(n).stream();
	}

	@Override
	public Node targetNode(Edge e) {
		return g.getEdgeTarget(e);
	}

	@Override
	public Stream<Node> startNodes() {
		return g.vertexSet().parallelStream();
	}

}