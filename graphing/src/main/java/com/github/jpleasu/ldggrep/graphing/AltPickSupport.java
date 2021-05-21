package com.github.jpleasu.ldggrep.graphing;

import static com.github.jpleasu.ldggrep.util.ReflectionUtil.*;

import java.awt.Component;
import java.awt.Shape;
import java.awt.geom.AffineTransform;
import java.awt.geom.Rectangle2D;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ConcurrentModificationException;

import javax.swing.CellRendererPane;

import org.jungrapht.visualization.*;
import org.jungrapht.visualization.MultiLayerTransformer.Layer;
import org.jungrapht.visualization.layout.model.LayoutModel;
import org.jungrapht.visualization.renderers.AbstractEdgeRenderer;
import org.jungrapht.visualization.renderers.HeayweightEdgeLabelRenderer;
import org.jungrapht.visualization.renderers.Renderer.Edge;
import org.jungrapht.visualization.renderers.Renderer.EdgeLabel;
import org.jungrapht.visualization.selection.ShapePickSupport;
import org.jungrapht.visualization.transform.*;
import org.jungrapht.visualization.transform.shape.GraphicsDecorator;

public final class AltPickSupport<EdgeT, VertexT> extends ShapePickSupport<VertexT, EdgeT> {

	private final Method prepareFinalEdgeShapeMethod;
	private final Edge<VertexT, EdgeT> edgeRenderer;
	private final HeayweightEdgeLabelRenderer<VertexT, EdgeT> edgeLabelRenderer;

	public AltPickSupport(VisualizationServer<VertexT, EdgeT> viewer) {
		super(viewer);
		edgeRenderer = viewer.getRenderer().getEdgeRenderer();
		if (edgeRenderer instanceof AbstractEdgeRenderer) {
			prepareFinalEdgeShapeMethod =
				getMethod(edgeRenderer.getClass(), "prepareFinalEdgeShape");
			if (prepareFinalEdgeShapeMethod != null) {
				prepareFinalEdgeShapeMethod.setAccessible(true);
			}
		}
		else {
			prepareFinalEdgeShapeMethod = null;
		}
		EdgeLabel<VertexT, EdgeT> r = viewer.getRenderer().getEdgeLabelRenderer();
		if (r instanceof HeayweightEdgeLabelRenderer) {
			edgeLabelRenderer = (HeayweightEdgeLabelRenderer<VertexT, EdgeT>) r;
		}
		else {
			edgeLabelRenderer = null;
		}

	}

	@Override
	protected Shape prepareFinalEdgeShape(RenderContext<VertexT, EdgeT> renderContext,
			LayoutModel<VertexT> layoutModel, EdgeT e) {
		// jpleasu: use the actual renderer's finalEdgeShape
		if (prepareFinalEdgeShapeMethod != null) {
			int[] coords = new int[4];
			boolean[] loop = new boolean[1];
			try {
				return (Shape) prepareFinalEdgeShapeMethod.invoke(edgeRenderer, renderContext,
					layoutModel, e, coords, loop);
			}
			catch (IllegalAccessException | IllegalArgumentException
					| InvocationTargetException e1) {
				e1.printStackTrace();
			}
		}
		return super.prepareFinalEdgeShape(renderContext, layoutModel, e);
	}

	@Override
	public EdgeT getEdge(LayoutModel<VertexT> layoutModel, Rectangle2D pickFootprint) {
		EdgeT closest = null;
		MultiLayerTransformer multiLayerTransformer =
			vv.getRenderContext().getMultiLayerTransformer();
		MutableTransformer viewTransformer = multiLayerTransformer.getTransformer(Layer.VIEW);

		while (true) {
			try {
				for (EdgeT edge : getFilteredEdges()) {
					Shape edgeShape =
						prepareFinalEdgeShape(vv.getRenderContext(), layoutModel, edge);
					if (edgeShape == null) {
						continue;
					}

					edgeShape = viewTransformer.transform(edgeShape);
					if (viewTransformer instanceof LensTransformer) {
						LensTransformer lensTransformer = (LensTransformer) viewTransformer;
						edgeShape = lensTransformer.getDelegate().transform(edgeShape);
					}

					//Line2D endToEnd = invoke(this, "getLineFromShape", edgeShape);
					// jpleasu: removed the final term in the following conjunction
					if (!edgeShape.contains(pickFootprint) && edgeShape.intersects(pickFootprint)) {
						closest = edge;
						break;
					}

					// jpleasu: pick by label
					Shape edgeLabelShape =
						prepareEdgeLabelShape(vv.getRenderContext(), layoutModel, edge);
					if (edgeLabelShape == null) {
						continue;
					}
					if (edgeLabelShape.intersects(pickFootprint)) {
						closest = edge;
						break;
					}
				}
				break;
			}
			catch (ConcurrentModificationException cme) {
				//
			}
		}
		return closest;
	}

	private Shape prepareEdgeLabelShape(RenderContext<VertexT, EdgeT> renderContext,
			LayoutModel<VertexT> layoutModel, EdgeT edge) {
		if (edgeLabelRenderer != null) {
			String label = renderContext.getEdgeLabelFunction().apply(edge);
			GraphicsDecorator oldg = renderContext.getGraphicsContext();
			MyGraphicsDecorator g = new MyGraphicsDecorator();
			renderContext.setGraphicsContext(g);
			edgeLabelRenderer.labelEdge(renderContext, layoutModel, edge, label);
			renderContext.setGraphicsContext(oldg);
			return g.getShape();
		}
		return null;
	}
}

class MyGraphicsDecorator extends GraphicsDecorator {
	final static AffineTransform ID = new AffineTransform();
	private AffineTransform remembered;
	private int wi;
	private int he;

	@Override
	public AffineTransform getTransform() {
		return ID;
	}

	@Override
	public void setTransform(AffineTransform transform) {
		if (transform != ID) {
			remembered = transform;
		}
	}

	public void draw(Component c, CellRendererPane rendererPane, int x, int y, int w, int h,
			boolean shouldValidate) {
		this.wi = w;
		this.he = h;
	}

	public Rectangle2D getBounds() {
		return new Rectangle2D.Float(0, 0, wi, he);
	}

	public Shape getShape() {
		AffineTransformer xform = new AffineTransformer(remembered);
		return xform.transform(getBounds());
	}

}
