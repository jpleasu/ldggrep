package com.github.jpleasu.ldggrep;

import java.io.InputStream;
import java.io.OutputStream;
import java.util.*;
import java.util.Map.Entry;
import java.util.stream.Collectors;

import org.graalvm.polyglot.Context;
import org.graalvm.polyglot.Source;

import com.github.jpleasu.ldggrep.internal.Pred;
import com.github.jpleasu.ldggrep.internal.PredicateBuilder;
import com.github.jpleasu.ldggrep.parser.Predicate;
import com.github.jpleasu.ldggrep.util.Pair;

/**
 * A model for LDGs matched by LDGMatcher.
 * 
 * Includes methods for converting nodes and edges to strings and predicates.
 * 
 * NB: predicates that use state can easily violate regularity and produce unexpected results. 
 *
 * @param <N> the node type
 * @param <E> the edge type
 */
public class LDGModel<N, E> {
	protected Random random = new Random();

	/** node memory before filtering by liveness in computeMemory */
	protected Map<Integer, Set<Pair<Integer, N>>> storedNodes = new HashMap<>();
	/** node memory prior to match */
	protected Map<Integer, Set<N>> incomingMemory = new HashMap<>();

	Map<Integer, int[]> counts = new HashMap<>();

	/** called prior to match, the model has the opportunity to reset counters, etc */
	protected void clearMatchData() {
		counts.clear();
	}

	protected final MethodManager methodManager;

	private Context codeContext;
	final PredicateBuilder<N> nodeBuilder;
	final PredicateBuilder<E> edgeBuilder;

	public LDGModel() {
		this.methodManager = new MethodManager(this);

		this.nodeBuilder = new PredicateBuilder<N>(methodManager, NPred.class, this::nodeToString,
			this::nodeToCodeObject);
		this.edgeBuilder = new PredicateBuilder<E>(methodManager, EPred.class, this::edgeToString,
			this::edgeToCodeObject);
	}

	/**
	 * @param n a node from this model
	 * @return a string representation of {@code n} for use in literal and regular expression predicates
	 */
	public String nodeToString(N n) {
		return n.toString();
	}

	/**
	 * @param e an edge from this model
	 * @return a string representation of {@code e} for use in literal and regular expression predicates
	 */
	public String edgeToString(E e) {
		return e.toString();
	}

	/**
	 * @param n LDG node
	 * @return transformation of node for use in JavaScript code predicates
	 */
	protected Object nodeToCodeObject(N n) {
		return n;
	}

	/**
	 * @param e LDG edge
	 * @return transformation of edge for use in JavaScript code predicates
	 */
	protected Object edgeToCodeObject(E e) {
		return e;
	}

	public void bind(String varName, Object value) {
		codeContext.getBindings("js").putMember(varName, value);
	}

	/**
	 * @param source JavaScript source
	 * @return an object representing the evaluated result
	 */
	public Object eval(String source) {
		return codeContext.eval(Source.create("js", source));
	}

	public void initializeCodeContext() {
		initializeCodeContext(System.out, System.err, System.in);
	}

	// must be called before using [..] predicates.
	final protected void initializeCodeContext(OutputStream out, OutputStream err, InputStream in) {
		// must provide a classloader with truffle-api.jar available
		ClassLoader classLoader = LDGMatcher.class.getClassLoader();

		ClassLoader savedThreadClassloader = Thread.currentThread().getContextClassLoader();
		Thread.currentThread().setContextClassLoader(classLoader);
		try {
			codeContext = Context.newBuilder("js")
					.hostClassLoader(classLoader)
					.allowAllAccess(true)
					.out(out)
					.err(err)
					.in(in)
					.build();
			edgeBuilder.setCodeContext(codeContext);
			nodeBuilder.setCodeContext(codeContext);
		}
		finally {
			Thread.currentThread().setContextClassLoader(savedThreadClassloader);
		}
	}

	public void initializeCodeContext(OutputStream out) {
		initializeCodeContext(out, out, System.in);
	}

	public void initializeCodeContext(OutputStream out, OutputStream err) {
		initializeCodeContext(out, err, System.in);
	}

	final public Pred<E> buildEdgePred(Predicate p) {
		return edgeBuilder.buildPred(p);
	}

	final public Pred<N> buildNodePred(Predicate p) {
		return nodeBuilder.buildPred(p);
	}

	public void setIncomingMemory(Map<Integer, Set<N>> m) {
		this.incomingMemory = m;
	}

	/** 
	 * 
	 * After a match is computed, store the outgoing memory into the match and reset model's storage.
	 *  
	 * @param match the match object to receive memory
	 */
	public void copyOutgoingMemory(LDGMatch<N, E> match) {
		// filter dead nodes from the stored nodes
		if (!storedNodes.isEmpty()) {
			Set<Pair<Integer, N>> liveNodes =
				match.s2ps.values().stream().flatMap(Set::stream).collect(Collectors.toSet());

			for (Entry<Integer, Set<Pair<Integer, N>>> e : storedNodes.entrySet()) {
				HashSet<Pair<Integer, N>> ns = new HashSet<>(e.getValue());
				ns.retainAll(liveNodes);
				match.memory.put(e.getKey(),
					ns.stream().map(Pair::getRight).collect(Collectors.toSet()));
			}
			storedNodes = new HashMap<>();
		}
	}

	@NPred(description = "store node in outgoing slot S", args = { "S" })
	public boolean sto(int i, N n, int s) {
		storedNodes.computeIfAbsent(s, k -> new HashSet<>()).add(Pair.of(i, n));
		return true;
	}

	@NPred(description = "match nodes stored in incoming slot S", args = { "S" })
	public boolean mem(int i, N n, int s) {
		return incomingMemory.getOrDefault(s, Collections.emptySet()).contains(n);
	}

	@NPred(description = "randomly accept with probability NUM/DENOM", args = { "NUM", "DENOM" })
	@EPred(description = "randomly accept with probability NUM/DENOM", args = { "NUM", "DENOM" })
	public boolean rand(int i, N n, int num, int denom) {
		return random.nextInt(denom) < num;
	}

	@NPred(description = "accept if P = (hashCode(x) % NPARTS)", args = { "P", "NPARTS" })
	@EPred(description = "accept if P = (hashCode(x) % NPARTS)", args = { "P", "NPARTS" })
	public boolean part(int i, N n, int p, int nparts) {
		int x = (n.hashCode() % nparts);
		if (x < 0)
			x += nparts;
		return (p == x);
	}

	@NPred(description = "match at most M times during forward pass", args = { "M" })
	public boolean max(int i, N n, int m) {
		return ++counts.computeIfAbsent(i, k -> new int[] { 0 })[0] <= m;
	}

	public MethodManager getMethodManager() {
		return methodManager;
	}

}
