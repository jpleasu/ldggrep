/* TODO:
*  - Do fallthrough edges create too much bloat?  Just replace the targets of calls directly..
*  - filter link or node types that might be too much, like consts.
*  - add named local variables?
*    mv = cw.visitMethod(ACC_PUBLIC, "clazz", "(Lblah/Blah;)Z", null, null);
*    mv.visitLocalVariable("n", "Lblah/Blah;", null, l0, l1, 1);
*  - avoid Object::<init> bubbles
*  - lazily generated edges are stored too long, wasting memory.
*/
package com.github.jpleasu.ldggrep.java;

import java.io.*;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.nio.file.*;
import java.nio.file.FileSystem;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.*;
import java.util.jar.*;
import java.util.stream.Stream;

import org.objectweb.asm.*;
import org.objectweb.asm.util.*;

import com.github.jpleasu.ldggrep.*;

/**
 * A pattern matcher for java class files
 */

class JavaModel extends LDGModel<Node, Link<? extends Node, ? extends Node>> {
	JavaModel() {
		initializeCodeContext();
	}

	@NPred(value = "class", description = "a class or interface")
	public boolean clazz(Node n) {
		return n instanceof ClassNode;
	}

	@NPred(description = "a method")
	public boolean method(Node n) {
		return n instanceof MethodNode;
	}

	@NPred(description = "a data field")
	public boolean field(Node n) {
		return n instanceof FieldNode;
	}

	@NPred(value = "const", description = "a constant value")
	public boolean konst(Node n) {
		return n instanceof ConstNode;
	}

	@EPred(description = "a method call")
	public boolean call(Link<? extends Node, ? extends Node> l) {
		return l instanceof CallLink;
	}

	@NPred(
		description = "alias of \"</^(java\\.util\\.|java\\.lang\\.)/>\".. stuff you probably don't want to chain through"
	)
	public boolean corejava(Node n) {
		String na = null;
		if (n instanceof ClassNode) {
			na = ((ClassNode) n).name;
		}
		else if (n instanceof MethodNode) {
			na = ((MethodNode) n).cl.name;
		}
		if (na != null) {
			return na.startsWith("java.util.") || na.startsWith("java.lang.");
		}
		return false;
	}

	@EPred(
		description = "alias of \"(call|implementedby|fallthrough) <!corejava>\".. probably what you actually want"
	)
	public boolean callx(Link<? extends Node, ? extends Node> l) {
		return (call(l) || implementedby(l) | fallthrough(l)) && !corejava(l.dst);
	}

	@EPred(value = "return", description = "a method return type, e.g. <method> return <class> ")
	public boolean r3turn(Link<? extends Node, ? extends Node> l) {
		return l instanceof ReturnLink;
	}

	@EPred(description = "a constant or field reference")
	public boolean ref(Link<? extends Node, ? extends Node> l) {
		return l instanceof RefLink;
	}

	@EPred(
		description = "if ChildClass has no method \"meth\", any calls to it will fallthrough to its parent class, e.g. <ChildClass:meth> fallthrough <ParentClass:meth2>"
	)
	public boolean fallthrough(Link<? extends Node, ? extends Node> l) {
		return l instanceof FallsThroughLink;
	}

	@EPred(
		description = "if ChildClass implements the method \"meth\" of Parentclass/interface, then <ParentClass::meth> implementedby <ChildClass::meth>"
	)
	public boolean implementedby(Link<? extends Node, ? extends Node> l) {
		return l instanceof ImplementedByLink;
	}

	@EPred(value = "implements", description = "a class implements its interfaces")
	public boolean implementz(Link<? extends Node, ? extends Node> l) {
		return l instanceof ImplementsInterfaceLink;
	}

	@EPred(value = "extends", description = "a class extends its parent class")
	public boolean extendz(Link<? extends Node, ? extends Node> l) {
		return l instanceof ExtendsLink;
	}

	@EPred(description = "a class defines each of its methods")
	public boolean defines(Link<? extends Node, ? extends Node> l) {
		return l instanceof DefinesMethodLink;
	}

	@Override
	public String nodeToString(Node n) {
		return n.toString();
	}

	@Override
	public String edgeToString(Link<? extends Node, ? extends Node> e) {
		return e.toString();
	}
}

class JavaLDG implements LDG<Node, Link<? extends Node, ? extends Node>> {
	public JavaLDG(String[] paths) throws IOException {
		FileSystem fs = FileSystems.getDefault();
		for (String path : paths) {
			Path fp = fs.getPath(path);
			if (fp.toFile().isDirectory())
				ingestDirectory(fp);
			else
				ingestFile(fp.toFile());
		}
	}

	static class ModList<T> {
		final Collection<T> c;

		ModList(Collection<T> c) {
			this.c = c;
		}

		Collection<T> m;

		Collection<T> mod() {
			if (m == null)
				m = new ArrayList<>(c);
			return m;
		}

		Collection<T> get() {
			if (m == null)
				return c;
			return m;
		}
	}

	@Override
	public Stream<Link<? extends Node, ? extends Node>> outEdges(Node n) {
		ModList<Link<? extends Node, ? extends Node>> outLinks = new ModList<>(n.outLinks);

		// n is a method, c::m ..
		if (n instanceof MethodNode) {
			MethodNode mn = (MethodNode) n;
			// where c doesn't implement m ..
			if (!mn.cl.outLinks.stream().anyMatch(l -> l.dst.equals(n) /* replace with == ? */ )) {
				// if c has a super ..
				Optional<Link<? extends Node, ? extends Node>> ol =
					mn.cl.outLinks.stream().filter(ExtendsLink.class::isInstance).findFirst();
				if (ol.isPresent()) {
					ExtendsLink el = (ExtendsLink) ol.get();
					// add fallthrough to super(c)::m
					outLinks.mod()
							.add(
								new FallsThroughLink(mn, getNode(new MethodNode(el.dst, mn.name))));
				}
			}

			// implementedby by child(c)::m
			// where c has a child
			mn.cl.inLinks.stream()
					.filter(ExtendsLink.class::isInstance)
					.map(ExtendsLink.class::cast)
					.forEach(el -> {
						if (el.src.outLinks.stream()
								.filter(DefinesMethodLink.class::isInstance)
								.map(DefinesMethodLink.class::cast)
								.anyMatch(dm -> dm.dst.name.equals(mn.name)))
							outLinks.mod()
									.add(new ImplementedByLink(mn,
										getNode(new MethodNode(el.src, mn.name))));
					});

			mn.cl.inLinks.stream()
					.filter(ImplementsInterfaceLink.class::isInstance)
					.map(ImplementsInterfaceLink.class::cast)
					.forEach(el -> {
						if (el.src.outLinks.stream()
								.filter(DefinesMethodLink.class::isInstance)
								.map(DefinesMethodLink.class::cast)
								.anyMatch(dm -> dm.dst.name.equals(mn.name)))
							outLinks.mod()
									.add(new ImplementedByLink(mn,
										getNode(new MethodNode(el.src, mn.name))));
					});

		}

		return outLinks.get().stream();
	}

	@Override
	public Node targetNode(Link<? extends Node, ? extends Node> e) {
		// skip the query to the base graph since this edge might have been generated lazily
		return e.dst;
	}

	@Override
	public Stream<Node> startNodes() {
		return allNodes.keySet().parallelStream();
	}

	Map<Node, Node> allNodes = new HashMap<>();

	/** find the given node, returning the canonical representative, or assign it as the representative
	 *  
	 * @param node the representative 
	 * @param <N> the node type
	 * @return the canonical representative
	 */
	@SuppressWarnings("unchecked")
	<N extends Node> N getNode(N node) {
		return (N) allNodes.computeIfAbsent(node, x -> node);
	}

	@SuppressWarnings("unchecked")
	<N extends Node> N getExistingNode(N node) {
		return (N) allNodes.get(node);
	}

	<N0 extends Node, N1 extends Node> void addEdge(Class<? extends Link<N0, N1>> klass, N0 n0,
			N1 n1) {
		n0 = getNode(n0);
		n1 = getNode(n1);
		try {
			Constructor<? extends Link<N0, N1>> con =
				klass.getConstructor(n0.getClass(), n1.getClass());
			addEdge(con.newInstance(n0, n1));
		}
		catch (NoSuchMethodException | SecurityException | InstantiationException
				| IllegalAccessException | IllegalArgumentException | InvocationTargetException e) {
			throw new RuntimeException(e);
		}
	}

	void addEdge(Link<? extends Node, ? extends Node> e) {
		Node n0 = e.src;
		Node n1 = e.dst;
		n0.outLinks.add(e);
		n1.inLinks.add(e);
	}

	void ingestClassStream(InputStream instream) throws IOException {
		ClassReader cr = new ClassReader(instream);

		ClassNode cl0 = getNode(new ClassNode(cr.getClassName()));
		ClassNode super0 = getNode(new ClassNode(cr.getSuperName()));

		addEdge(new ExtendsLink(cl0, super0));
		for (String sinter0 : cr.getInterfaces()) {
			ClassNode inter0 = getNode(new ClassNode(sinter0));
			addEdge(new ImplementsInterfaceLink(cl0, inter0));
		}

		cr.accept(new ClassVisitor(Opcodes.ASM9) {
			public MethodVisitor visitMethod(int access, String methname, String methdesc,
					String signature, String[] exceptions) {
				final MethodNode md0 = getNode(new MethodNode(cl0, methname));

				String rettype = Type.getReturnType(methdesc).getClassName();
				if (rettype != null && !"void".equals(rettype))
					addEdge(new ReturnLink(md0, getNode(new ClassNode(rettype))));

				addEdge(new DefinesMethodLink(cl0, md0));
				return new MethodVisitor(api) {
					@Override
					public void visitFieldInsn(int opcode, String owner, String name, String desc) {
						addEdge(new RefLink(md0,
							getNode(new FieldNode(getNode(new ClassNode(owner)), name))));
						super.visitFieldInsn(opcode, owner, name, desc);
					}

					@Override
					public void visitLdcInsn(Object cst) {
						addEdge(new RefLink(md0, getNode(new ConstNode(cst))));
						super.visitLdcInsn(cst);
					}

					@Override
					public void visitIntInsn(int opcode, int operand) {
						if (opcode == Opcodes.SIPUSH)
							addEdge(new RefLink(md0, getNode(new ConstNode(operand))));
						super.visitIntInsn(opcode, operand);
					}

					public void visitMethodInsn(int opcode, String owner, String called_methname,
							String desc, boolean itf) {
						addEdge(new CallLink(md0, getNode(
							new MethodNode(getNode(new ClassNode(owner)), called_methname))));
						super.visitMethodInsn(opcode, owner, called_methname, desc, itf);
					}
				};
			}
		}, 0 /* ClassReader.EXPAND_FRAMES */ );
		// dumpClass(new PrintWriter(System.err), cr);
	}

	@SuppressWarnings("unused")
	private void dumpClass(Writer out, ClassReader cr) {
		cr.accept(new TraceClassVisitor(null, new Textifier(), new PrintWriter(out)),
			ClassReader.EXPAND_FRAMES);
		cr.accept(new TraceClassVisitor(null, new ASMifier(), new PrintWriter(out)),
			ClassReader.EXPAND_FRAMES);
	}

	void ingestJarfile(JarFile jf) throws IOException {
		Enumeration<JarEntry> jes = jf.entries();
		while (jes.hasMoreElements()) {
			JarEntry je = jes.nextElement();
			String jen = je.getName();
			if (jen.endsWith(".class")) {
				ingestClassStream(jf.getInputStream(je));
			}
			else if (jen.endsWith(".jar")) {
				ingestJarStream(jf.getInputStream(je));
			}
		}
	}

	void ingestJarStream(InputStream is) throws IOException {
		JarInputStream jis = new JarInputStream(is, false);
		while (true) {
			JarEntry je;
			je = jis.getNextJarEntry();

			if (je == null) {
				break;
			}
			String jen = je.getName();
			if (jen.endsWith(".class")) {
				ingestClassStream(jis);
			}
			else if (jen.endsWith(".jar")) {
				ingestJarStream(jis);
			}
			jis.closeEntry();
		}
	}

	void ingestClassFile(File classFile) throws FileNotFoundException, IOException {
		try (FileInputStream fis = new FileInputStream(classFile)) {
			ingestClassStream(fis);
		}
	}

	void ingestFile(File file) throws IOException {
		if (file.toString().endsWith(".class")) {
			ingestClassFile(file);
		}
		else if (file.toString().endsWith(".jar")) {
			try (JarFile jf = new JarFile(file)) {
				ingestJarfile(jf);
			}
		}
	}

	void ingestDirectory(Path startingDir) throws IOException {
		Files.walkFileTree(startingDir, new SimpleFileVisitor<Path>() {
			@Override
			public FileVisitResult visitFile(Path file, BasicFileAttributes attrs)
					throws IOException {
				ingestFile(file.toFile());
				return FileVisitResult.CONTINUE;
			}
		});
	}
}

public class JavaGrepShell extends BaseLDGGrepShell<Node, Link<? extends Node, ? extends Node>> {
	String[] paths;

	public static void main(String[] args) throws Exception {
		new JavaGrepShell(args).startREPL();
	}

	public JavaGrepShell(String[] paths) {
		this.paths = paths;
	}

	@Override
	protected JavaModel newModel() {
		return new JavaModel();
	}

	@Override
	protected LDG<Node, Link<? extends Node, ? extends Node>> newLDG() {
		try {
			return new JavaLDG(paths);
		}
		catch (IOException e) {
			e.printStackTrace();
		}
		return null;
	}
}
