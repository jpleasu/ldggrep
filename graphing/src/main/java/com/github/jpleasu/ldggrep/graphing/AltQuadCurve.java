package com.github.jpleasu.ldggrep.graphing;

import java.awt.Shape;
import java.awt.geom.QuadCurve2D;
import java.util.*;

import org.jgrapht.Graph;
import org.jungrapht.visualization.decorators.EdgeShape;
import org.jungrapht.visualization.decorators.ParallelEdgeShapeFunction;
import org.jungrapht.visualization.util.EdgeIndexFunction;

/**
 * a custom edge shape 
 *
 * @param <V> vertex type
 * @param <E> edge type
 */
public class AltQuadCurve<V, E> extends ParallelEdgeShapeFunction<V, E> {
	final static QuadCurve2D QUAD_CURVE = new QuadCurve2D.Float();

	// edge labels are placed at index * font_height from the straight line of an edge.. which will
	// change with the closeness setting.  see parallelOffset in HeayweightEdgeLabelRenderer#labelEdge
	public static float QCURVE_CTRLY_MULTIPLIER = 1.8f;
	public static float A_GOOD_CLOSENESS_TO_USE = .65f;

	@SuppressWarnings("unchecked")
	public Shape apply(Graph<V, E> graph, E edge) {
		V source = graph.getEdgeSource(edge);
		V target = graph.getEdgeTarget(edge);
		if (source.equals(target)) {
			return EdgeShape.loop.apply(graph, edge);
		}

		float controlY = (controlOffsetIncrement + 1) * edgeIndexFunction.apply(graph, edge);

		QUAD_CURVE.setCurve(0.0f, 0.0f, 0.5f, QCURVE_CTRLY_MULTIPLIER * controlY, 1.0f, 0.0f);
		return QUAD_CURVE;
	}

	static public class IndexFunc<V, E> implements EdgeIndexFunction<V, E> {
		protected Map<E, Integer> edgeIndex = new HashMap<>();

		@Override
		public Integer apply(Graph<V, E> graph, E edge) {
			Integer index = edgeIndex.get(edge);
			if (index == null) {
				V v0 = graph.getEdgeSource(edge);
				V v1 = graph.getEdgeTarget(edge);
				Set<E> forwardEdges = graph.getAllEdges(v0, v1);
				Set<E> reverseEdges = graph.getAllEdges(v1, v0);

				int totalEdges = forwardEdges.size() + reverseEdges.size();

				// odd #edges: 0, 1, -1, 2, -2, ...
				// even #edges: 1, -1, 2, -2, ... 
				int count = ((totalEdges & 1) == 1) ? 1 : 2;
				for (E connectingEdge : forwardEdges) {
					edgeIndex.put(connectingEdge, (count >> 1) * ((count & 1) == 0 ? 1 : -1));
					++count;
				}
				for (E connectingEdge : reverseEdges) {
					edgeIndex.put(connectingEdge, (count >> 1) * ((count & 1) == 0 ? -1 : 1));
					++count;
				}
				index = edgeIndex.getOrDefault(edge, 0);
			}
			return index;
		}

	}
}