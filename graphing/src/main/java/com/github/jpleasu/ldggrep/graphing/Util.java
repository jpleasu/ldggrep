package com.github.jpleasu.ldggrep.graphing;

import java.awt.*;
import java.awt.event.*;
import java.util.*;
import java.util.Map.Entry;
import java.util.concurrent.ForkJoinPool;
import java.util.function.Predicate;

import javax.swing.*;
import javax.swing.Timer;

import org.jgrapht.Graph;
import org.jungrapht.visualization.MultiLayerTransformer.Layer;
import org.jungrapht.visualization.VisualizationScrollPane;
import org.jungrapht.visualization.VisualizationViewer;
import org.jungrapht.visualization.layout.algorithms.*;
import org.jungrapht.visualization.layout.algorithms.LayoutAlgorithm.Builder;
import org.jungrapht.visualization.layout.algorithms.repulsion.BarnesHutFA2Repulsion;
import org.jungrapht.visualization.util.LayoutAlgorithmTransition;

import com.github.jpleasu.ldggrep.LDGMatch;
import com.github.jpleasu.ldggrep.LDGModel;
import com.github.jpleasu.ldggrep.util.Pair;

import dk.brics.automaton.State;

public class Util {

	public static int ITERATIVE_LAYOUT_TIMEOUT_MS = 2000;

	static public class JgtMatchEdge<N, E>
			extends Pair<Pair<Set<Pair<Integer, N>>, Set<Pair<Integer, N>>>, E> {
		protected JgtMatchEdge(Set<Pair<Integer, N>> src, Set<Pair<Integer, N>> target, E edge) {
			super(Pair.of(src, target), edge);
		}

		Set<Pair<Integer, N>> getSource() {
			return getLeft().getLeft();
		}

		Set<Pair<Integer, N>> getTarget() {
			return getLeft().getRight();
		}

		E getEdge() {
			return getRight();
		}
	}

	public static <N, E> Graph<Set<Pair<Integer, N>>, JgtMatchEdge<N, E>> toGraph(
			LDGModel<N, E> model, LDGMatch<N, E> match) {
		JgtGraphBuilder<N, E, Set<Pair<Integer, N>>, JgtMatchEdge<N, E>> graphBuilder =
			new JgtGraphBuilder<>(model, match) {

				@Override
				protected JgtMatchEdge<N, E> newet(Set<Pair<Integer, N>> ps0,
						Set<Pair<Integer, N>> ps1, E e) {
					return new JgtMatchEdge<>(ps0, ps1, e);
				}

				@Override
				protected Set<Pair<Integer, N>> ps2vt(Set<Pair<Integer, N>> ps) {
					return ps;
				}

			};
		return graphBuilder.buildGraph();
	}

	private static <V, E> LinkedHashMap<String, Builder<V, ? extends LayoutAlgorithm<V>, ?>> getLayouts(
			VisualizationViewer<V, E> viewer, Predicate<V> rootPredicate) {
		LinkedHashMap<String, Builder<V, ? extends LayoutAlgorithm<V>, ?>> m =
			new LinkedHashMap<>();

		@SuppressWarnings("unchecked")
		Builder<V, ? extends LayoutAlgorithm<V>, ?> typeFixedBuilder =
			(Builder<V, ? extends LayoutAlgorithm<V>, ?>) ForceAtlas2LayoutAlgorithm.builder()
					.repulsionContractBuilder(BarnesHutFA2Repulsion.builder().repulsionK(50));

		m.put("EdgeAware Tree", EdgeAwareTreeLayoutAlgorithm.<V, E> edgeAwareBuilder());
		m.put("EdgeAwareMultirow Tree",
			MultiRowEdgeAwareTreeLayoutAlgorithm.<V, E> edgeAwareBuilder());
		m.put("Tree", TreeLayoutAlgorithm.<V> builder());
		m.put("Tidier Tree", TidierTreeLayoutAlgorithm.<V, E> edgeAwareBuilder());
		m.put("Tidier Radial Tree", TidierRadialTreeLayoutAlgorithm.<V, E> edgeAwareBuilder());
		m.put("Multirow Tree", MultiRowTreeLayoutAlgorithm.<V> builder());
		m.put("Fruchterman Reingold", FRLayoutAlgorithm.<V> builder());
		m.put("Radial", RadialTreeLayoutAlgorithm.<V> builder());
		m.put("EdgeAwareRadial", RadialEdgeAwareTreeLayoutAlgorithm.<V, E> edgeAwareBuilder());
		m.put("Kamada Kawai", KKLayoutAlgorithm.<V> builder());
		m.put("Self Organizing Map", ISOMLayoutAlgorithm.<V> builder());
		m.put("DAG", DAGLayoutAlgorithm.<V, E> builder());
		m.put("Circle", CircleLayoutAlgorithm.<V> builder().reduceEdgeCrossing(false));
		m.put("Reduced Xing Circle", CircleLayoutAlgorithm.<V> builder().reduceEdgeCrossing(true));
		m.put("ForceAtlas2", typeFixedBuilder);
		m.put("Spring", SpringLayoutAlgorithm.<V, E> builder());
		m.put("GEM", GEMLayoutAlgorithm.<V, E> edgeAwareBuilder());
		m.put("Balloon", BalloonLayoutAlgorithm.<V> builder());

		ForkJoinPool pool = ForkJoinPool.commonPool();

		for (Builder<V, ? extends LayoutAlgorithm<V>, ?> builder : m.values()) {
			if (builder instanceof AbstractTreeLayoutAlgorithm.Builder) {
				((AbstractTreeLayoutAlgorithm.Builder<V, ?, ?>) builder)
						.rootPredicate(rootPredicate);
			}
			if (builder instanceof AbstractIterativeLayoutAlgorithm.Builder) {
				((AbstractIterativeLayoutAlgorithm.Builder<V, ?, ?>) builder).executor(r -> {
					Timer timer = new Timer(ITERATIVE_LAYOUT_TIMEOUT_MS, (e) -> {
						viewer.getVisualizationModel().getLayoutAlgorithm().cancel();
					});
					timer.setRepeats(false);
					timer.start();
					pool.execute(() -> {
						r.run();
						timer.stop();
					});
				});
			}
		}
		return m;
	}

	public static <N, E> void showJungrapht(LDGModel<N, E> model, LDGMatch<N, E> match,
			String title) {

		Set<Set<Pair<Integer, N>>> initialVertices = new HashSet<>();
		Set<Set<Pair<Integer, N>>> finalVertices = new HashSet<>();
		for (Entry<State, Set<Pair<Integer, N>>> matchEnt : match.s2ps.entrySet()) {
			if (match.initialStates.contains(matchEnt.getKey()))
				initialVertices.add(matchEnt.getValue());
			if (match.finalStates.contains(matchEnt.getKey()))
				finalVertices.add(matchEnt.getValue());
		}

		VisualizationViewer<Set<Pair<Integer, N>>, JgtMatchEdge<N, E>> viewer = VisualizationViewer
				.<Set<Pair<Integer, N>>, JgtMatchEdge<N, E>> builder(toGraph(model, match))
				.viewSize(new Dimension(1024, 768))
				.build();

		JgtGraphViewer<N, E, Set<Pair<Integer, N>>, JgtMatchEdge<N, E>> graphViewer =
			new JgtGraphViewer<>(model, match, viewer) {

				@Override
				protected Set<Pair<Integer, N>> vt2ps(Set<Pair<Integer, N>> vt) {
					return vt;
				}

				@Override
				protected boolean isFinal(Set<Pair<Integer, N>> vt) {
					return finalVertices.contains(vt);
				}

				@Override
				protected boolean isInitial(Set<Pair<Integer, N>> vt) {
					return initialVertices.contains(vt);
				}

				@Override
				protected E et2e(JgtMatchEdge<N, E> et) {
					return et.getEdge();
				}

				@Override
				protected void vtSelectionChanged(boolean selected,
						Collection<Set<Pair<Integer, N>>> selection) {
					String status = selected ? "selected" : "deselected";
					System.err.printf("%s %s\n", selection, status);
				}

				@Override
				protected void etSelectionChanged(boolean selected,
						Collection<JgtMatchEdge<N, E>> selection) {
					String status = selected ? "selected" : "deselected";
					System.err.printf("%s %s\n", selection, status);
				}

				@Override
				protected String getHelpText() {
					return super.getHelpText() + "\n<b>ctrl W</b> <i>closes</i> window\n";
				}
			};

		graphViewer.configure();

		JComponent c = viewer.getComponent();
		String actionName = "JgtGraphViewer" + graphViewer.hashCode();
		c.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW)
				.put(KeyStroke.getKeyStroke("ctrl W"), actionName);
		c.getActionMap().put(actionName, new AbstractAction() {
			@Override
			public void actionPerformed(ActionEvent e) {
				Window w = SwingUtilities.windowForComponent(c);
				w.dispatchEvent(new WindowEvent(w, WindowEvent.WINDOW_CLOSING));
			}
		});

		viewer.scaleToLayout();

		JToolBar toolBar = new JToolBar("Still draggable");
		toolBar.setOrientation(SwingConstants.HORIZONTAL);
		LinkedHashMap<String, Builder<Set<Pair<Integer, N>>, ? extends LayoutAlgorithm<Set<Pair<Integer, N>>>, ?>> layoutMap =
			getLayouts(viewer, n -> {
				return n.stream().anyMatch(x -> x.getLeft() == 0);
			});

		final JComboBox<String> layoutCombo =
			new JComboBox<>(layoutMap.keySet().toArray(new String[0])) {
				public Dimension getMaximumSize() {
					return getPreferredSize();
				}
			};
		layoutCombo.addActionListener(e -> {
			viewer.reset();
			LayoutAlgorithm<Set<Pair<Integer, N>>> layoutAlgorithm =
				layoutMap.get(layoutCombo.getSelectedItem()).build();
			LayoutAlgorithmTransition.apply(viewer, layoutAlgorithm, viewer::scaleToLayout);
		});
		toolBar.add(layoutCombo);

		// set layout after reconfigure to allow for LayoutStateChange listener to fire on layout complete
		layoutCombo.setSelectedIndex(0);

		JButton button;
		button = new JButton("reset view");
		button.addActionListener(e -> {
			viewer.getRenderContext()
					.getMultiLayerTransformer()
					.getTransformer(Layer.LAYOUT)
					.setToIdentity();
			viewer.getRenderContext()
					.getMultiLayerTransformer()
					.getTransformer(Layer.VIEW)
					.setToIdentity();
			viewer.scaleToLayout();
		});
		toolBar.add(button);

		button = new JButton("fit");
		button.addActionListener(e -> {
			graphViewer.fit();
		});
		toolBar.add(button);

		button = new JButton("jiggle");
		button.addActionListener(e -> {
			graphViewer.jiggle();
		});
		toolBar.add(button);

		button = new JButton("contract");
		button.addActionListener(e -> {
			graphViewer.contract();
		});
		toolBar.add(button);

		button = new JButton("expand");
		button.addActionListener(e -> {
			graphViewer.expand();
		});
		toolBar.add(button);

		button = new JButton("rotate 90");
		button.addActionListener(e -> {
			graphViewer.rotate90();
		});
		toolBar.add(button);

		button = new JButton("xstretch");
		button.addActionListener(e -> {
			graphViewer.xstretch();
		});
		toolBar.add(button);

		button = new JButton("help");
		button.addActionListener(e -> {
			graphViewer.showHelpDialog();
		});
		toolBar.add(button);

		// display
		JFrame frame = new JFrame(title);
		frame.setDefaultCloseOperation(WindowConstants.DISPOSE_ON_CLOSE);
		Container content = frame.getContentPane();
		content.add(new VisualizationScrollPane(viewer), BorderLayout.CENTER);
		content.add(toolBar, BorderLayout.NORTH);
		frame.pack();
		frame.setVisible(true);
	}

}
