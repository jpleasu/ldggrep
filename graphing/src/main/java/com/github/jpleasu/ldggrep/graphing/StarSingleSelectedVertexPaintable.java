package com.github.jpleasu.ldggrep.graphing;

import static org.jungrapht.visualization.renderers.BiModalRenderer.*;

import java.awt.*;
import java.awt.geom.AffineTransform;
import java.awt.geom.Point2D;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;

import javax.swing.JComponent;

import org.jungrapht.visualization.MultiLayerTransformer;
import org.jungrapht.visualization.VisualizationServer;
import org.jungrapht.visualization.layout.model.LayoutModel;
import org.jungrapht.visualization.layout.model.Point;
import org.jungrapht.visualization.renderers.*;
import org.jungrapht.visualization.transform.shape.GraphicsDecorator;
import org.jungrapht.visualization.transform.shape.TransformingGraphics;

import com.github.jpleasu.ldggrep.util.Pair;

/*
 * mostly copied from Jungrapht 1.3 SingleSelectedVertexPaintable
 */
public class StarSingleSelectedVertexPaintable<V, E> implements VisualizationServer.Paintable {
	private final VisualizationServer<V, E> visualizationServer;
	private Shape selectionShape;
	private Paint selectionPaint;

	private BiModalSelectionRenderer<V, E> biModalRenderer;

	protected Function<VisualizationServer<V, E>, V> selectedVertexFunction;

	public StarSingleSelectedVertexPaintable(VisualizationServer<V, E> visualizationServer,
			Paint selectionPaint, float scale) {
		this.visualizationServer = visualizationServer;
		this.selectionShape = createSelectionShape(scale);
		this.selectionPaint = selectionPaint;
		this.biModalRenderer = BiModalSelectionRenderer.<V, E> builder()
				.component(visualizationServer.getComponent())
				.lightweightRenderer(
					new SelectionRenderer<>(new LightweightVertexSelectionRenderer<>()))
				.heavyweightRenderer(
					(new SelectionRenderer<>(new HeavyweightVertexSelectionRenderer<>())))
				.modeSourceRenderer((BiModalRenderer<V, E>) visualizationServer.getRenderer())
				.build();
		this.selectedVertexFunction = vs -> getSelectedVertex(visualizationServer);
	}

	static private <V, E> V getSelectedVertex(VisualizationServer<V, E> vv) {
		return vv.getSelectedVertexState()
				.getSelected()
				.stream()
				.filter(v -> vv.getRenderContext().getVertexIncludePredicate().test(v))
				.findFirst()
				.orElse(null);
	}

	private static List<Pair<Integer, Integer>> points(int... cl) {
		List<Pair<Integer, Integer>> r = new ArrayList<>(cl.length / 2);
		for (int i = 0; i + 1 < cl.length; i += 2) {
			r.add(Pair.of(cl[i], cl[i + 1]));
		}
		return r;
	}

	protected Shape createSelectionShape(float scale) {
		List<Pair<Integer, Integer>> points =
			points(-10, 0, -1, 1, 0, 10, 1, 1, 10, 0, 1, -1, 0, -10, -1, -1);
		Shape shape = new Polygon(points.stream().mapToInt(Pair::getLeft).toArray(),
			points.stream().mapToInt(Pair::getRight).toArray(), points.size());
		AffineTransform transform = new AffineTransform();
		//transform.translate(-15, 15);
		transform.scale(scale / 10f, scale / 10f);
		//transform.rotate(Math.PI / 4);
		return transform.createTransformedShape(shape);
	}

	/**
	 * Draw shapes to indicate selected vertices
	 *
	 * @param g the {@code Graphics} to draw with
	 */
	@Override
	public void paint(Graphics g) {
		// get the g2d
		Graphics2D g2d = (Graphics2D) g;
		// save off old Paint and AffineTransform
		Paint oldPaint = g2d.getPaint();
		AffineTransform oldTransform = g2d.getTransform();
		// set the new color
		g2d.setPaint(selectionPaint);

		V selectedVertex = selectedVertexFunction.apply(visualizationServer);

		if (selectedVertex != null && visualizationServer.getRenderContext()
				.getVertexIncludePredicate()
				.test(selectedVertex)) {

			GraphicsDecorator graphicsDecorator =
				visualizationServer.getRenderContext().getGraphicsContext();

			if (graphicsDecorator instanceof TransformingGraphics) {
				AffineTransform graphicsTransformCopy = new AffineTransform(g2d.getTransform());

				AffineTransform viewTransform = visualizationServer.getRenderContext()
						.getMultiLayerTransformer()
						.getTransformer(MultiLayerTransformer.Layer.VIEW)
						.getTransform();

				// don't mutate the viewTransform!
				graphicsTransformCopy.concatenate(viewTransform);
				g2d.setTransform(graphicsTransformCopy);
				paintSingleTransformed(selectedVertex);

			}
			else {
				((JComponent) visualizationServer).revalidate();
				paintSingleNormal(g2d, selectedVertex);
			}
			// put back the old values
			g2d.setPaint(oldPaint);
			g2d.setTransform(oldTransform);
		}
	}

	@SuppressWarnings({ "rawtypes", "unchecked" })
	protected void paintSingleTransformed(V vertex) {
		Function<V, Shape> oldShapeFunction =
			visualizationServer.getRenderContext().getVertexShapeFunction();
		visualizationServer.getRenderContext().setVertexShapeFunction(v -> selectionShape);
		Function<V, Shape> oldLightweightShapeFunction =
			((LightweightVertexSelectionRenderer) biModalRenderer.getVertexRenderer(LIGHTWEIGHT))
					.getVertexShapeFunction();
		((LightweightVertexSelectionRenderer) biModalRenderer.getVertexRenderer(LIGHTWEIGHT))
				.setVertexShapeFunction(v -> selectionShape);

		biModalRenderer.renderVertex(visualizationServer.getRenderContext(),
			visualizationServer.getVisualizationModel().getLayoutModel(), vertex);

		visualizationServer.getRenderContext().setVertexShapeFunction(oldShapeFunction);
		((LightweightVertexSelectionRenderer) biModalRenderer.getVertexRenderer(LIGHTWEIGHT))
				.setVertexShapeFunction(oldLightweightShapeFunction);
	}

	protected void paintSingleNormal(Graphics2D g2d, V vertex) {
		LayoutModel<V> layoutModel = visualizationServer.getVisualizationModel().getLayoutModel();
		MultiLayerTransformer multiLayerTransformer =
			visualizationServer.getRenderContext().getMultiLayerTransformer();

		Point location = layoutModel.apply(vertex);
		Point2D viewLocation = multiLayerTransformer.transform(location.x, location.y);
		Shape shape = AffineTransform.getTranslateInstance(viewLocation.getX(), viewLocation.getY())
				.createTransformedShape(selectionShape);
		g2d.draw(shape);
		g2d.fill(shape);
	}

	@Override
	public boolean useTransform() {
		return false;
	}
}
