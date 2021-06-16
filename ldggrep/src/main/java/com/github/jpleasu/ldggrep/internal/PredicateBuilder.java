package com.github.jpleasu.ldggrep.internal;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.*;
import java.util.function.Function;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import org.graalvm.polyglot.*;

import com.github.jpleasu.ldggrep.BoundMethod;
import com.github.jpleasu.ldggrep.parser.*;
import com.github.jpleasu.ldggrep.util.ClassUtils;

/**
 * builds predicates for the predicate machine using AST nodes from the parser.
 *
 * @param <X> either the node or edge type of an LDG - the predicate argument type
 */
public class PredicateBuilder<X> {
	// keys are bareword expressions, including arguments
	final Map<String, Pred<X>> methodPredicateCache = new HashMap<>();

	private Context codeContext;

	final Map<String, BoundMethod> methodMap;
	final Function<X, Object> xToCode;
	final Function<X, String> xToString;

	public PredicateBuilder(Map<String, BoundMethod> methodMap, Function<X, String> xToString,
			Function<X, Object> xToCode) {
		this.methodMap = methodMap;
		this.xToString = xToString;
		this.xToCode = xToCode;
	}

	/**
	 * set the code context sued to compile code predicates.  This must be done 
	 * before {@link PredicateBuilder#buildCodePredicate(CodePred)} is called. 
	 * 
	 * @param ctx context for compiling code predicates
	 */
	public void setCodeContext(Object ctx) {
		codeContext = (Context) ctx;
	}

	protected Pred<X> buildMethodPredicate(BarePred bwp) {
		// find the predicate method corresponding to the type, edge or node, and bareword
		BoundMethod boundMethod = methodMap.get(bwp.name);
		if (boundMethod == null) {
			throw new RuntimeException(
				String.format("No method corresponds to bareword \"%s\"", bwp.name));
		}
		Method method = boundMethod.method;
		final Object methodThiz = boundMethod.obj;
		method.setAccessible(true);
		Class<?>[] methodArgTypes = method.getParameterTypes();

		String[] infoArgs = boundMethod.info.args;

		// validate number of args from query expression against method annotation
		{
			String prototype = bwp.name;
			if (infoArgs.length > 0) {
				prototype += '(';
				prototype += Arrays.stream(infoArgs).collect(Collectors.joining(","));
				prototype += ')';
			}

			if (bwp.args.size() < infoArgs.length) {
				throw new RuntimeException(
					String.format("Too few arguments to predicate %s from %s in expression \"%s\"",
						prototype, methodThiz.getClass().getName(), bwp.toString()));
			}
			if (bwp.args.size() > infoArgs.length) {
				throw new RuntimeException(
					String.format("Too many arguments to predicate %s from %s in expression \"%s\"",
						prototype, methodThiz.getClass().getName(), bwp.toString()));
			}
		}

		// construct arguments for method invocation
		boolean usesPredicateMachineState;
		int firstArgPos;
		if (methodArgTypes.length - infoArgs.length == 2) {
			if (!ClassUtils.isAssignable(methodArgTypes[0], int.class))
				throw new RuntimeException(String.format(
					"Based on argument count, first argument of predicate method \"%s\" must be int, not  %s",
					method.getName(), methodArgTypes[0].getName()));
			usesPredicateMachineState = true;
			firstArgPos = 2;
		}
		else if (methodArgTypes.length - infoArgs.length == 1) {
			usesPredicateMachineState = false;
			firstArgPos = 1;
		}
		else {
			throw new RuntimeException(String.format(
				"Misconfigured predicate method %s: method must take either 1 (the node) or 2 (predicate machine state + node) more arguments than args",
				method.getName()));
		}
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
		if (!usesPredicateMachineState) {
			return new MethPred<X>(bwp.toString(), method, methodThiz, methodArgs) {
				@Override
				public boolean matches(int i, X x) {
					args[0] = x;
					return invoke();
				}
			};
		}
		return new MethPred<X>(bwp.toString(), method, methodThiz, methodArgs) {
			@Override
			public boolean matches(int i, X x) {
				args[0] = i;
				args[1] = x;
				return invoke();
			}
		};
	}

	protected Pred<X> buildLiteralPredicate(LiteralPred p) {
		return (i, x) -> p.value.equals(xToString.apply(x));
	}

	protected Pred<X> buildRegexPredicate(RegexPred p) {
		return new Pred<X>() {
			@Override
			public String toString() {
				return String.format("/%s/", pat.toString());
			}

			final Pattern pat = Pattern.compile(p.re.replaceAll("\\/", "/"));

			@Override
			public boolean matches(int i, X x) {
				return pat.matcher(xToString.apply(x)).find();
			}
		};
	}

	@SuppressWarnings("unchecked")
	protected Pred<X> buildCodePredicate(CodePred p) {
		if (codeContext == null) {
			throw new RuntimeException("must set code context before building code predicates");
		}
		String codeSrc = "(function(x) {with(x) {return !!(" + p.code + ");}})";
		Value codeObj = codeContext.eval(Source.create("js", codeSrc));
		if (codeObj == null) {
			throw new RuntimeException("failed to compile: " + codeSrc);
		}
		final Function<Object, Boolean> f = codeObj.as(Function.class);
		if (f == null) {
			throw new RuntimeException("failed to compile: " + codeSrc);
		}
		return (i, x) -> f.apply(xToCode.apply(x));
	}

	protected Pred<X> buildBarePredicate(BarePred bwp) {
		Pred<X> pred =
			methodPredicateCache.computeIfAbsent(bwp.toString(), k -> buildMethodPredicate(bwp));
		if (pred == null) {
			throw new RuntimeException(
				String.format("unknown barework predicate \"%s\"", bwp.name));
		}
		return pred;
	}

	protected Pred<X> buildNotPredicate(NotPred p) {
		final Pred<X> ip = buildPred(p.p);
		return (i, e) -> {
			return !ip.matches(i, e);
		};
	}

	final public Pred<X> buildPred(Predicate p) {
		if (p instanceof LiteralPred)
			return buildLiteralPredicate((LiteralPred) p);
		else if (p instanceof RegexPred)
			return buildRegexPredicate((RegexPred) p);
		else if (p instanceof CodePred)
			return buildCodePredicate((CodePred) p);
		else if (p instanceof BarePred)
			return buildBarePredicate((BarePred) p);
		else if (p instanceof AnyPred)
			return (i, e) -> true;
		else if (p instanceof NotPred)
			return buildNotPredicate((NotPred) p);
		else
			return null;
	}

	private static abstract class MethPred<X> implements Pred<X> {
		final String n;
		final Method m;
		final Object thiz;
		final Object[] args;

		protected MethPred(String n, Method m, Object thiz, Object[] args) {
			this.n = n;
			this.m = m;
			this.thiz = thiz;
			this.args = args;
		}

		@Override
		public String toString() {
			return n;
		}

		protected boolean invoke() {
			try {
				return (boolean) m.invoke(thiz, args);
			}
			catch (IllegalAccessException | IllegalArgumentException
					| InvocationTargetException e1) {
				throw new RuntimeException(e1);
			}
		}
	}

}
