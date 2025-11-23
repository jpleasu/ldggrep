package com.github.jpleasu.ldggrep.ghidra.gui;

import static com.github.jpleasu.ldggrep.util.ReflectionUtil.*;

import java.util.*;

import javax.swing.KeyStroke;

import org.jungrapht.visualization.VisualizationViewer;
import org.jungrapht.visualization.layout.model.LayoutModel;

import com.github.jpleasu.ldggrep.LDGMatch;
import com.github.jpleasu.ldggrep.LDGModel;
import com.github.jpleasu.ldggrep.ghidra.BaseGhidraGrep;
import com.github.jpleasu.ldggrep.graphing.JgtGraphViewer;
import com.github.jpleasu.ldggrep.util.Pair;

import docking.action.builder.ActionBuilder;
import ghidra.graph.visualization.DefaultGraphDisplay;
import ghidra.graph.visualization.DefaultGraphDisplayComponentProvider;
import ghidra.graph.visualization.DefaultGraphDisplayWrapper;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.service.graph.*;
import resources.Icons;
import resources.MultiIcon;
import resources.icons.TranslateIcon;

public class GhidraJgtGraphViewer<N, E> extends JgtGraphViewer<N, E, AttributedVertex, AttributedEdge> {
	DefaultGraphDisplayWrapper graphDisplay;
	final DefaultGraphDisplayComponentProvider componentProvider;
	final LayoutModel<AttributedVertex> layoutModel;
	final BaseGhidraGrep<N, E> scr;
	final AttributedGraph graph;
	final Map<String, Set<Pair<Integer, N>>> vtid2ps;
	final Map<String, E> etid2e;

	static DefaultGraphDisplay getDelegate(DefaultGraphDisplayWrapper graphDisplay) {
		return getField(graphDisplay, "delegate");
	}

	static VisualizationViewer<AttributedVertex, AttributedEdge> getViewer(DefaultGraphDisplayWrapper graphDisplay) {
		return getField(getDelegate(graphDisplay), "viewer");
	}

	public GhidraJgtGraphViewer(BaseGhidraGrep<N, E> scr, LDGModel<N, E> model, LDGMatch<N, E> match,
			DefaultGraphDisplayWrapper graphDisplay) {
		super(model, match, getViewer(graphDisplay));

		this.scr = scr;
		this.graphDisplay = graphDisplay;

		componentProvider = getField(getDelegate(graphDisplay), "componentProvider");
		layoutModel = viewer.getVisualizationModel().getLayoutModel();

		GhidraJgtGraphBuilder<N, E> graphBuilder = new GhidraJgtGraphBuilder<>(model, match);
		this.graph = new AttributedGraph("LDGGrep",
				new GraphType("LDGGrep Graph", "LDGGrep Graph Type", List.of(), List.of()), "LDGGrep", false);
		graphBuilder.buildGraph(graph);
		this.vtid2ps = graphBuilder.vtid2ps;
		this.etid2e = graphBuilder.etid2e;
	}

	@Override
	protected Set<Pair<Integer, N>> vt2ps(AttributedVertex vt) {
		return vtid2ps.get(vt.getId());
	}

	@Override
	protected boolean isFinal(AttributedVertex vt) {
		return vt.hasAttribute(GhidraJgtGraphBuilder.FINAL_ATTR_NAME);
	}

	@Override
	protected boolean isInitial(AttributedVertex vt) {
		return vt.hasAttribute(GhidraJgtGraphBuilder.INITIAL_ATTR_NAME);
	}

	@Override
	protected E et2e(AttributedEdge et) {
		return etid2e.get(et.getId());
	}

	Address p2a(AttributedVertex vt) {
		return scr.nodeToAddress(vt2ps(vt).iterator().next().getRight());
	}

	@Override
	protected void vtSelectionChanged(boolean selected, Collection<AttributedVertex> collection) {
		if (selected) {
			Address addr = p2a(collection.iterator().next());
			scr.goTo(addr);
		}
		updateCurrentSelection();
	}

	@Override
	protected void etSelectionChanged(boolean selected, Collection<AttributedEdge> collection) {
		if (selected) {
			E e = et2e(collection.iterator().next());
			scr.goTo(scr.edgeToAddress(e));
		}
	}

	protected void updateCurrentSelection() {
		AddressSet addrs = new AddressSet();
		for (AttributedVertex vt : viewer.getSelectedVertexState().getSelected()) {
			scr.addToSelection(addrs, vt2ps(vt));
		}
		scr.setCurrentSelection(addrs);
	}

	void addActions() {
		new ActionBuilder("Jiggle", "GraphServices").toolBarIcon(Icons.NOT_ALLOWED_ICON)
				.description("Jiggle overlapping labels elements to be more readable").onAction(context -> jiggle())
				.buildAndInstallLocal(componentProvider);

		new ActionBuilder("Contract", "GraphServices").toolBarIcon(Icons.COLLAPSE_ALL_ICON)
				.description("Contract nodes").onAction(context -> contract()).buildAndInstallLocal(componentProvider);

		new ActionBuilder("Expand", "GraphServices").toolBarIcon(Icons.EXPAND_ALL_ICON)
				.description("Expand nodes to be more readable").onAction(context -> expand())
				.buildAndInstallLocal(componentProvider);

		MultiIcon ico = new MultiIcon(Icons.LEFT_ICON, new TranslateIcon(Icons.RIGHT_ICON, 5, 0) {
			@Override
			public int getIconWidth() {
				return super.getIconWidth() + 5;
			}
		});
		new ActionBuilder("XStrech", "GraphServices").toolBarIcon(ico).description("Horizontally stretch")
				.onAction(context -> xstretch()).buildAndInstallLocal(componentProvider);

		new ActionBuilder("Rotate90", "GraphServices").toolBarIcon(Icons.REFRESH_ICON)
				.description("Rotate graph 90 degrees").onAction(context -> rotate90())
				.buildAndInstallLocal(componentProvider);

		new ActionBuilder("Close", "GraphServices").description("Close graph")
				.keyBinding(KeyStroke.getKeyStroke("ctrl W")).onAction(context -> componentProvider.closeComponent())
				.buildAndInstallLocal(componentProvider);
	}

	@Override
	protected String getHelpText() {
		return super.getHelpText() + "\n<b>ctrl W</b> <i>closes</i> graph window\n";
	}

	public int getGraphSize() {
		return graph.getVertexCount();
	}

	public void show() {
		addActions();
		configure();
		var options = new GraphDisplayOptions(graph.getGraphType());
		options.setMaxNodeCount(50000);
		graphDisplay.setGraph(graph, options, getClass().getName(), false,
				scr.getMonitor());
	}
}
