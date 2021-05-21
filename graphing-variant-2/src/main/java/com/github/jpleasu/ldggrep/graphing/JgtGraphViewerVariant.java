package com.github.jpleasu.ldggrep.graphing;

import java.awt.event.InputEvent;

import org.jungrapht.visualization.RenderContext;
import org.jungrapht.visualization.VisualizationViewer;
import org.jungrapht.visualization.VisualizationViewer.GraphMouse;
import org.jungrapht.visualization.control.*;
import org.jungrapht.visualization.decorators.GradientEdgePaintFunction;

class JgtGraphViewerVariant<N, E, VertexT, EdgeT> {
	final protected VisualizationViewer<VertexT, EdgeT> viewer;

	public JgtGraphViewerVariant(VisualizationViewer<VertexT, EdgeT> viewer) {
		this.viewer = viewer;
	}

	protected void variantConfigure() {
		RenderContext<VertexT, EdgeT> renderContext = viewer.getRenderContext();
		renderContext.setEdgeDrawPaintFunction(new GradientEdgePaintFunction<>(viewer));
	}

	protected GraphMouse createGraphMouse() {
		return new DefaultGraphMouse<>(DefaultGraphMouse.builder().vertexSelectionOnly(false)) {
			public void loadPlugins() {
				add(new SelectingGraphMousePlugin<>(SelectingGraphMousePlugin.builder()
						.singleSelectionMask(InputEvent.BUTTON1_DOWN_MASK)
						.toggleSingleSelectionMask(
							InputEvent.BUTTON1_DOWN_MASK | InputEvent.SHIFT_DOWN_MASK)));
				add(new RegionSelectingGraphMousePlugin<>());
				add(TranslatingGraphMousePlugin.builder()
						.translatingMask(InputEvent.BUTTON1_DOWN_MASK)
						.build());
				add(RotatingGraphMousePlugin.builder()
						.rotatingMask(InputEvent.BUTTON1_DOWN_MASK | InputEvent.SHIFT_DOWN_MASK)
						.build());
				add(new ScalingGraphMousePlugin());
				setPluginsLoaded();
			}
		};
	}

	protected String getHelpText() {
		//@formatter:off
		return 
				"[press <b>escape</b> to close help window]\n"+
				"\n"+		
				"without modifiers:\n"+
				"  <b>left click< and drag</b> <i>pans</i>\n"+
				"with <b>shift</b>:\n"+
				"  <b>left click and drag</b> <i>rotates</i> about center of view\n"+
				"with <b>ctrl</b>:\n"+
				"  <b>left click</b> <i>selects</i>\n" +
				"  <b>left click</b> on vertex and <b>drag</b> (selects and) <i>moves</i> selection\n"+
				"     o/w <i>selects vertices in rectangle</i>\n"+
				"with <b>ctrl+shift</b>:\n"+
				"  <b>left click</b> <i>adds</i> to selection\n" +
				"  <b>left click</b> on vertex and <b>drag</b> (adds to selection and) <i>moves</i>\n"+
				"     o/w <i>adds vertices in rectangle</i> to selection\n"+
				""
				;
		//@formatter:on
	}

}