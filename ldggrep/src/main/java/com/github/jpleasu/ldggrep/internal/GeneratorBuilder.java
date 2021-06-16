package com.github.jpleasu.ldggrep.internal;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.*;
import java.util.stream.Stream;

import com.github.jpleasu.ldggrep.*;
import com.github.jpleasu.ldggrep.parser.*;
import com.github.jpleasu.ldggrep.util.ClassUtils;

/**
 * builds generators for the matcher using AST nodes from the parser.
 *
 * @param <N> the node type 
 * @param <E> the edge type
 */
public class GeneratorBuilder<N, E> {
	// keys are bareword expressions, including arguments
	final Map<String, Generator<N, E>> methodGeneratorCache = new HashMap<>();

	final Map<String, BoundMethod> methodMap;

	public GeneratorBuilder(Map<String, BoundMethod> methodMap) {
		this.methodMap = methodMap;
	}

	protected Generator<N, E> buildMethodGen(BarePred bwp) {
		BoundMethod boundMethod = methodMap.get(bwp.name);
		if (boundMethod == null) {
			return null;
		}
		Method method = boundMethod.method;
		final Object methodThiz = boundMethod.obj;
		method.setAccessible(true);
		Class<?>[] methodArgTypes = method.getParameterTypes();

		String[] infoArgs = boundMethod.info.args;

		if (methodArgTypes.length - infoArgs.length != 1) {
			throw new RuntimeException(String.format(
				"Misconfigured generator method %s: method must take 1 more argument than args of the NPred %s",
				method.getName(), bwp.name));
		}
		int firstArgPos = 1;

		final Object[] methodArgs = new Object[firstArgPos + bwp.args.size()];
		for (int i = 0; i < bwp.args.size(); ++i) {
			Object bwArg = bwp.args.get(i);

			if (!ClassUtils.isAssignable(methodArgTypes[firstArgPos + i], bwArg.getClass()))
				throw new RuntimeException(
					String.format("\"%s\" takes a %s in position %d, but \"%s\" called with a %s",
						method.getName(), methodArgTypes[firstArgPos + i].getName(), i, bwArg,
						bwArg.getClass().getName()));
			methodArgs[firstArgPos + i] = bwp.args.get(i);
		}

		// create and return the predicate
		return new MethGen<N, E>(bwp.toString(), method, methodThiz, methodArgs) {
			@Override
			public Stream<N> startNodes(LDG<N, E> g) {
				args[0] = g;
				return invoke();
			}
		};
	}

	protected Generator<N, E> buildLiteralPredicate(LiteralPred p) {
		return buildMethodGen(new BarePred(StartGen.LITERAL, List.of(p.value)));
	}

	protected Generator<N, E> buildRegexPredicate(RegexPred p) {
		return buildMethodGen(new BarePred(StartGen.REGEX, List.of(p.re)));
	}

	protected Generator<N, E> buildCodePredicate(CodePred p) {
		return null;
	}

	protected Generator<N, E> buildBarePredicate(BarePred bwp) {
		Generator<N, E> gen =
			methodGeneratorCache.computeIfAbsent(bwp.toString(), k -> buildMethodGen(bwp));
		return gen;
	}

	protected Generator<N, E> buildNotPredicate(NotPred p) {
		return null;
	}

	final public Generator<N, E> buildGen(Predicate p) {
		if (p instanceof LiteralPred)
			return buildLiteralPredicate((LiteralPred) p);
		else if (p instanceof RegexPred)
			return buildRegexPredicate((RegexPred) p);
		else if (p instanceof CodePred)
			return buildCodePredicate((CodePred) p);
		else if (p instanceof BarePred)
			return buildBarePredicate((BarePred) p);
		else if (p instanceof AnyPred)
			return null;
		else if (p instanceof NotPred)
			return buildNotPredicate((NotPred) p);
		else
			return null;
	}

	private static abstract class MethGen<N, E> implements Generator<N, E> {
		final String n;
		final Method m;
		final Object thiz;
		final Object[] args;

		protected MethGen(String n, Method m, Object thiz, Object[] args) {
			this.n = n;
			this.m = m;
			this.thiz = thiz;
			this.args = args;
		}

		@Override
		public String toString() {
			return n;
		}

		@SuppressWarnings("unchecked")
		protected Stream<N> invoke() {
			try {
				return (Stream<N>) m.invoke(thiz, args);
			}
			catch (IllegalAccessException | IllegalArgumentException
					| InvocationTargetException e1) {
				throw new RuntimeException(e1);
			}
		}
	}

}
