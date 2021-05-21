package com.github.jpleasu.ldggrep.internal;

import java.lang.annotation.Annotation;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.*;
import java.util.function.Function;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import org.graalvm.polyglot.*;

import com.github.jpleasu.ldggrep.MethodManager;
import com.github.jpleasu.ldggrep.MethodManager.BoundMethod;
import com.github.jpleasu.ldggrep.parser.*;
import com.github.jpleasu.ldggrep.util.ClassUtils;

/**
 * builds predicate for the predicate machine from AST nodes from the parser.
 *
 * @param <X> either the node or edge type of an LDG
 */
public class PredicateBuilder<X> {
	final Map<String, Pred<X>> barewords = new HashMap<>();
	final Class<? extends Annotation> xAnnotationClass;
	final Function<X, String> xToString;

	final MethodManager methodManager;
	private Context codeContext;

	final Function<X, Object> xToCode;

	public PredicateBuilder(MethodManager methodManager,
			Class<? extends Annotation> xAnnotationClass, Function<X, String> xToString,
			Function<X, Object> xToCode) {
		this.methodManager = methodManager;
		this.xAnnotationClass = xAnnotationClass;
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
		BoundMethod boundMethod = methodManager.find(xAnnotationClass, bwp.name);
		if (boundMethod == null) {
			throw new RuntimeException(
				String.format("No method corresponds to bareword \"%s\"", bwp.name));
		}
		Method method = boundMethod.method;
		final Object methodThiz = boundMethod.obj;
		method.setAccessible(true);
		Class<?>[] methodArgTypes = method.getParameterTypes();

		XPred xpred = new XPred(xAnnotationClass, method);
		String[] predicateArgs = xpred.args;

		// validate number of args from query expression against method annotation
		{
			String predicatePrototype = bwp.name;
			if (predicateArgs.length > 0) {
				predicatePrototype += '(';
				predicatePrototype += Arrays.stream(predicateArgs).collect(Collectors.joining(","));
				predicatePrototype += ')';
			}

			if (bwp.args.size() < predicateArgs.length) {
				throw new RuntimeException(
					String.format("Too few arguments to predicate %s from %s in expression \"%s\"",
						predicatePrototype, methodThiz.getClass().getName(), bwp.toString()));
			}
			if (bwp.args.size() > predicateArgs.length) {
				throw new RuntimeException(
					String.format("Too many arguments to predicate %s from %s in expression \"%s\"",
						predicatePrototype, methodThiz.getClass().getName(), bwp.toString()));
			}
		}

		// construct arguments for method invocation
		boolean usesPredicateMachineState;
		int firstPredicateArgPos;
		if (methodArgTypes.length - predicateArgs.length == 2) {
			if (!ClassUtils.isAssignable(methodArgTypes[0], int.class))
				throw new RuntimeException(String.format(
					"Based on argument count, first argument of predicate method \"%s\" must be int, not  %s",
					method.getName(), methodArgTypes[0].getName()));
			usesPredicateMachineState = true;
			firstPredicateArgPos = 2;
		}
		else if (methodArgTypes.length - predicateArgs.length == 1) {
			usesPredicateMachineState = false;
			firstPredicateArgPos = 1;
		}
		else {
			throw new RuntimeException(String.format(
				"Misconfigured predicate method %s: method must take either 1 (the node) or 2 (predicate machine state + node) more arguments than args",
				method.getName()));
		}
		final Object[] methodArgs = new Object[firstPredicateArgPos + bwp.args.size()];
		for (int i = 0; i < bwp.args.size(); ++i) {
			Object bwArg = bwp.args.get(i);

			if (!ClassUtils.isAssignable(methodArgTypes[firstPredicateArgPos + i],
				bwArg.getClass()))
				throw new RuntimeException(
					String.format("\"%s\" takes a %s in position %d, but \"%s\" called with a %s",
						method.getName(), methodArgTypes[firstPredicateArgPos + i].getName(), i,
						bwArg, bwArg.getClass().getName()));
			methodArgs[firstPredicateArgPos + i] = bwp.args.get(i);
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
		Pred<X> pred = barewords.computeIfAbsent(bwp.toString(), k -> buildMethodPredicate(bwp));
		if (pred == null) {
			throw new RuntimeException(String.format("\"%s\" is not a valid %s bareword",
				xAnnotationClass.getSimpleName(), bwp.name));
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
