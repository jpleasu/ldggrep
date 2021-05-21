package com.github.jpleasu.ldggrep.graphing;

import static com.github.jpleasu.ldggrep.util.ReflectionUtil.*;

import java.awt.*;
import java.awt.Dimension;
import java.awt.event.*;
import java.awt.font.FontRenderContext;
import java.awt.font.TextLayout;
import java.awt.geom.*;
import java.util.*;
import java.util.List;
import java.util.function.*;
import java.util.stream.Collectors;

import javax.swing.*;
import javax.swing.text.Document;
import javax.swing.text.html.HTMLEditorKit;
import javax.swing.text.html.StyleSheet;

import org.jgrapht.Graph;
import org.jungrapht.visualization.MultiLayerTransformer.Layer;
import org.jungrapht.visualization.RenderContext;
import org.jungrapht.visualization.VisualizationServer.Paintable;
import org.jungrapht.visualization.VisualizationViewer;
import org.jungrapht.visualization.annotations.MultiSelectedVertexPaintable;
import org.jungrapht.visualization.layout.model.LayoutModel;
import org.jungrapht.visualization.layout.model.Point;
import org.jungrapht.visualization.layout.model.Rectangle;
import org.jungrapht.visualization.renderers.JLabelEdgeLabelRenderer;
import org.jungrapht.visualization.renderers.ModalRenderer;
import org.jungrapht.visualization.renderers.Renderer;
import org.jungrapht.visualization.selection.MultiMutableSelectedState;

import com.github.jpleasu.ldggrep.LDGMatch;
import com.github.jpleasu.ldggrep.LDGModel;
import com.github.jpleasu.ldggrep.util.Pair;

abstract public class JgtGraphViewer<N, E, VertexT, EdgeT>
		extends JgtGraphViewerVariant<N, E, VertexT, EdgeT> {

	final protected LDGModel<N, E> model;
	final protected LDGMatch<N, E> match;

	public JgtGraphViewer(LDGModel<N, E> model, LDGMatch<N, E> match,
			VisualizationViewer<VertexT, EdgeT> viewer) {
		super(viewer);
		this.model = model;
		this.match = match;
	}

	protected abstract Set<Pair<Integer, N>> vt2ps(VertexT vt);

	protected abstract boolean isFinal(VertexT vt);

	protected abstract boolean isInitial(VertexT vt);

	protected abstract E et2e(EdgeT et);

	static Font VERTEX_LABEL_FONT = new Font(Font.MONOSPACED, Font.PLAIN, 18);
	static final float MIN_VERTEX_LABEL_WIDTH = 40;

	static Color VERTEX_BORDER_COLOR = new Color(0, 0, 0, 0x7f);
	static Color SELECTED_VERTEX_COLOR = Color.RED;

	static Font EDGE_LABEL_FONT = new Font(Font.MONOSPACED, Font.PLAIN, 14);
	static Color EDGE_LABEL_COLOR = Color.GRAY;
	static Color EDGE_COLOR = Color.GRAY;
	static Color SELECTED_EDGE_LABEL_COLOR = Color.RED;
	static Color SELECTED_EDGE_COLOR = Color.RED;

	static Color STATE_COLOR_DEFAULT = softenColor(Color.BLUE, 4);
	static Color STATE_COLOR_INITIAL = softenColor(Color.GREEN, 2.5f);
	static Color STATE_COLOR_FINAL = softenColor(Color.RED, 3);
	static Color STATE_COLOR_INITIAL_AND_FINAL = softenColor(Color.YELLOW, 3);

	static final int ARROW_SIZE = 10;

	static Color softenColor(Color c, float factor) {
		int r = c.getRed();
		int g = c.getGreen();
		int b = c.getBlue();
		int alpha = c.getAlpha();
		float[] hsbvals = Color.RGBtoHSB(r, g, b, null);
		Color c2 = Color.getHSBColor(hsbvals[0], hsbvals[1] / factor, hsbvals[2]);
		return new Color(c2.getRed(), c2.getGreen(), c2.getBlue(), alpha);
	}

	static Color clarifyColor(Color c, int newAlpha) {
		int r = c.getRed();
		int g = c.getGreen();
		int b = c.getBlue();
		return new Color(r, g, b, newAlpha);
	}

	protected void vtSelectionChanged(boolean selected, Collection<VertexT> collection) {
		//
	}

	protected void etSelectionChanged(boolean selected, Collection<EdgeT> collection) {
		//
	}

	@SuppressWarnings("unchecked")
	protected void configureSelection() {
		MultiMutableSelectedState<VertexT> vertexState = new ItemSetMultiMutableSelectedState<>();
		viewer.setSelectedVertexState(vertexState);
		vertexState.addItemListener(e -> {
			vtSelectionChanged(e.getStateChange() == ItemEvent.SELECTED,
				(Collection<VertexT>) e.getItem());
		});

		MultiMutableSelectedState<EdgeT> edgeState = new ItemSetMultiMutableSelectedState<>();
		viewer.setSelectedEdgeState(edgeState);
		edgeState.addItemListener(e -> {
			etSelectionChanged(e.getStateChange() == ItemEvent.SELECTED,
				(Collection<EdgeT>) e.getItem());
		});
	}

	/**
	 * (re)configure viewer with LDGGrep styling and behavior
	 */
	public void configure() {
		configureSelection();

		viewer.setToolTipText(null);

		RenderContext<VertexT, EdgeT> renderContext = viewer.getRenderContext();

		// node
		Function<VertexT, String> vertexLabeler = (sp) -> vt2ps(sp).stream()
				.map(p -> model.nodeToString(p.getRight()))
				.distinct()
				.collect(Collectors.joining(","));

		renderContext.setVertexStrokeFunction(nt -> new BasicStroke(1.5f));
		renderContext.setVertexDrawPaintFunction(vt -> VERTEX_BORDER_COLOR);

		renderContext.setVertexLabelFunction(vertexLabeler);
		renderContext.setVertexLabelPosition(Renderer.VertexLabel.Position.CNTR);
		renderContext.setVertexFontFunction(v -> VERTEX_LABEL_FONT);
		renderContext.setVertexShapeFunction(n -> {
			String label = vertexLabeler.apply(n);

			FontRenderContext fontRenderContext = new FontRenderContext(null, true, true);

			TextLayout textLayout = new TextLayout(label, VERTEX_LABEL_FONT, fontRenderContext);
			Rectangle2D bounds = textLayout.getBounds();
			//Rectangle2D bounds = VERTEX_LABEL_FONT.getStringBounds(label, fontRenderContext);

			float w = (float) bounds.getWidth();
			w = Math.max(w, MIN_VERTEX_LABEL_WIDTH) + 20;
			float h = (float) bounds.getHeight() + 20;
			return new RoundRectangle2D.Float(-w / 2, -h / 2, w, h, 20f, 20f);
		});

		renderContext.setVertexIconFunction(v -> null);
		renderContext.setVertexFillPaintFunction(vt -> {
			boolean isInitial = isInitial(vt);
			boolean isFinal = isFinal(vt);

			if (isInitial && isFinal)
				return STATE_COLOR_INITIAL_AND_FINAL;
			if (isInitial)
				return STATE_COLOR_INITIAL;
			if (isFinal)
				return STATE_COLOR_FINAL;
			return STATE_COLOR_DEFAULT;
		});

		// edge

		renderContext.setEdgeLabelFunction(et -> model.edgeToString(et2e(et)));
		JLabelEdgeLabelRenderer edgeLabelRenderer =
			new JLabelEdgeLabelRenderer(SELECTED_EDGE_LABEL_COLOR, true) {
				public <ET> Component getEdgeLabelRendererComponent(JComponent vv, Object value,
						Font font, boolean isSelected, ET edge) {

					setForeground(EDGE_LABEL_COLOR);
					if (isSelected) {
						setForeground(pickedEdgeLabelColor);
					}
					super.setBackground(vv.getBackground());

					if (font != null) {
						setFont(font);
					}
					else {
						setFont(vv.getFont());
					}
					setIcon(null);
					setBorder(noFocusBorder);
					setValue(value);
					return this;
				}
			};
		renderContext.setEdgeLabelRenderer(edgeLabelRenderer);

		renderContext.setEdgeFontFunction(et -> EDGE_LABEL_FONT);
		renderContext.setEdgeLabelCloseness(AltQuadCurve.A_GOOD_CLOSENESS_TO_USE);
		renderContext.setParallelEdgeIndexFunction(new AltQuadCurve.IndexFunc<>());
		renderContext.setEdgeShapeFunction(new AltQuadCurve<>());

		Function<EdgeT, Paint> edgeDrawPaint = et -> {
			if (viewer.getSelectedEdgeState().getSelected().contains(et)) {
				return SELECTED_EDGE_COLOR;
			}
			return EDGE_COLOR;
		};
		renderContext.setEdgeDrawPaintFunction(edgeDrawPaint);
		renderContext.setEdgeStrokeFunction(et -> {
			if (viewer.getSelectedEdgeState().getSelected().contains(et)) {
				return new BasicStroke(3f);
			}
			return new BasicStroke(1f);
		});
		renderContext.setEdgeWidth(1f);
		renderContext.setEdgeArrowWidth(ARROW_SIZE);
		renderContext.setEdgeArrowLength(ARROW_SIZE);
		renderContext.setArrowFillPaintFunction(edgeDrawPaint);
		renderContext.setArrowDrawPaintFunction(edgeDrawPaint);

		viewer.setGraphMouse(createGraphMouse());

		List<Paintable> postRenderers = getField(viewer, "postRenderers");
		postRenderers.clear();

		List<Paintable> preRenderers = getField(viewer, "preRenderers");
		preRenderers.clear();

		MultiSelectedVertexPaintable<VertexT, EdgeT> multiSelectedVertexPaintable =
			MultiSelectedVertexPaintable.builder(viewer)
					.selectionStrokeMin(8f)
					.selectionPaint(SELECTED_VERTEX_COLOR)
					.useBounds(false)
					.build();

		// cross that's barely visible when labels are at 100%
		var singleSelectedVertexPaintable = new StarSingleSelectedVertexPaintable<>(viewer,
			clarifyColor(SELECTED_VERTEX_COLOR, 0x7f), VERTEX_LABEL_FONT.getSize2D() * 2);

		viewer.addPreRenderPaintable(multiSelectedVertexPaintable);
		viewer.addPreRenderPaintable(singleSelectedVertexPaintable);

		// a hack to allow straight edges that happen to be shapes to be selected
		viewer.setPickSupport(new AltPickSupport<EdgeT, VertexT>(viewer));
		// viewer.setSelectedEdgeState(new MultiMutableSelectedState<>());

		// a hack to keep us in HEAVYWEIGHT mode
		ModalRenderer<VertexT, EdgeT> modalRenderer = viewer.getRenderer();
		Predicate<Supplier<Integer>> countPredicate = t -> false;
		setField(modalRenderer, "countPredicate", countPredicate);

		viewer.getVisualizationModel()
				.getLayoutModel()
				.getLayoutStateChangeSupport()
				.addLayoutStateChangeListener(e -> {
					if (!e.active) {
						rotate90();
						fit();
					}
				});

		// handle version specific reconfiguration
		variantConfigure();
	}

	protected void rotate90() {
		final LayoutModel<VertexT> layoutModel = viewer.getVisualizationModel().getLayoutModel();
		final Graph<VertexT, EdgeT> graph = viewer.getVisualizationModel().getGraph();

		double w = layoutModel.getWidth();
		double h = layoutModel.getHeight();

		for (VertexT vert : graph.vertexSet()) {
			Point p = layoutModel.get(vert);
			p = p.add(-w / 2, -h / 2);
			p = Point.of(p.y, -p.x);
			p = p.add(w / 2, h / 2);
			layoutModel.set(vert, p);
		}
		layoutModel.setSize((int) h, (int) w);
	}

	protected void xstretch() {
		final LayoutModel<VertexT> layoutModel = viewer.getVisualizationModel().getLayoutModel();
		final Graph<VertexT, EdgeT> graph = viewer.getVisualizationModel().getGraph();

		Point c = layoutModel.getCenter();
		graph.vertexSet().forEach(v -> {
			Point p = layoutModel.get(v);
			p = Point.of(2 * (p.x - c.x) + c.x, p.y);
			layoutModel.set(v, p);
		});

		layoutModel.resizeToSurroundingRectangle();
		viewer.repaint();
	}

	protected void contract() {
		final LayoutModel<VertexT> layoutModel = viewer.getVisualizationModel().getLayoutModel();
		final Graph<VertexT, EdgeT> graph = viewer.getVisualizationModel().getGraph();

		Point2D at = viewer.getCenter();
		viewer.getRenderContext()
				.getMultiLayerTransformer()
				.getTransformer(Layer.VIEW)
				.scale(.5, .5, at);
		graph.vertexSet().forEach(v -> {
			Point p = layoutModel.get(v);
			p = Point.of(2 * p.x, 2 * p.y);
			layoutModel.set(v, p);
		});

		layoutModel.setSize(2 * layoutModel.getWidth(), 2 * layoutModel.getHeight());
		viewer.repaint();
	}

	protected void expand() {
		final LayoutModel<VertexT> layoutModel = viewer.getVisualizationModel().getLayoutModel();
		final Graph<VertexT, EdgeT> graph = viewer.getVisualizationModel().getGraph();

		Point2D at = viewer.getCenter();
		viewer.getRenderContext()
				.getMultiLayerTransformer()
				.getTransformer(Layer.VIEW)
				.scale(2, 2, at);
		graph.vertexSet().forEach(v -> {
			Point p = layoutModel.get(v);
			p = Point.of(.5 * p.x, .5 * p.y);
			layoutModel.set(v, p);
		});

		layoutModel.setSize(layoutModel.getWidth() / 2, layoutModel.getHeight() / 2);
		viewer.repaint();
	}

	protected void fit() {
		final LayoutModel<VertexT> layoutModel = viewer.getVisualizationModel().getLayoutModel();
		layoutModel.resizeToSurroundingRectangle();
		viewer.repaint();
	}

	protected void jiggle() {
		final LayoutModel<VertexT> layoutModel = viewer.getVisualizationModel().getLayoutModel();
		final Graph<VertexT, EdgeT> graph = viewer.getVisualizationModel().getGraph();

		Function<VertexT, Rectangle> vbounds0 = viewer.getRenderContext().getVertexBoundsFunction();
		Function<VertexT, Rectangle> vbounds = v -> {
			Point p = layoutModel.get(v);
			Rectangle b = vbounds0.apply(v);
			return b.offset(p.x, p.y);
		};

		Random rando = new Random();

		List<VertexT> verts = graph.vertexSet().stream().sorted((v1, v2) -> {
			Point p1 = layoutModel.get(v1);
			Point p2 = layoutModel.get(v2);
			double d = p1.x - p2.x;
			if (d == 0.0) {
				d = p1.y - p2.y;
			}
			return (int) d;
		}).collect(Collectors.toList());
		for (int i = 0; i < verts.size(); ++i) {
			VertexT v1 = verts.get(i);
			Rectangle b1 = vbounds.apply(v1);
			for (int j = i + 1; j < verts.size(); ++j) {
				VertexT v2 = verts.get(j);
				Rectangle b2 = vbounds.apply(v2);
				if (b1.intersects(b2)) {
					double dy = b2.getCenterY() - b1.getCenterY();
					Point p2 = layoutModel.get(v2);
					int sgn = rando.nextDouble() > .5 ? +1 : -1;
					p2 = Point.of(p2.x, p2.y - dy + b1.height * 2.1 * sgn);
					layoutModel.set(v2, p2);
				}
			}
		}
	}

	protected JComponent createHelpComponent() {
		JEditorPane editorPane = new JEditorPane();
		editorPane.setEditable(false);
		JScrollPane scrollPane = new JScrollPane(editorPane);

		HTMLEditorKit kit = new HTMLEditorKit();
		editorPane.setEditorKit(kit);

		StyleSheet styleSheet = kit.getStyleSheet();
		styleSheet.addRule("body {font-size:16pt; }");

		Document doc = kit.createDefaultDocument();
		editorPane.setDocument(doc);

		editorPane.setText("<html><body><pre>" + getHelpText() + "</pre></body></html>");

		return scrollPane;
	}

	protected JDialog helpDialog;

	protected void showHelpDialog() {
		if (helpDialog == null) {
			Component c = viewer.getComponent();
			while (c != null) {
				if (c instanceof Frame) {
					break;
				}
				c = c.getParent();
			}
			Frame frame = (Frame) c;
			// try to pin this dialog to a main frame.. if we can't, dispose on close
			helpDialog = new JDialog(frame, false) {
				@Override
				protected void processWindowEvent(WindowEvent e) {
					super.processWindowEvent(e);
					if (e.getID() == WindowEvent.WINDOW_CLOSING) {

						if (frame != null) {
							setVisible(false);
						}
						else {
							dispose();
							helpDialog = null;
						}
					}
				}
			};
			JRootPane rootpane = helpDialog.getRootPane();
			rootpane.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW)
					.put(KeyStroke.getKeyStroke("ESCAPE"), "helpDialogClose");
			rootpane.getActionMap().put("helpDialogClose", new AbstractAction() {
				@Override
				public void actionPerformed(ActionEvent e) {
					helpDialog
							.dispatchEvent(new WindowEvent(helpDialog, WindowEvent.WINDOW_CLOSING));
				}
			});
			helpDialog.add(createHelpComponent());
			helpDialog.pack();
			helpDialog.setMinimumSize(new Dimension(400, 400));
			helpDialog.setVisible(true);
		}
		else

		{
			helpDialog.setVisible(!helpDialog.isVisible());
		}
	}
}
