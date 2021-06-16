package com.github.jpleasu.ldggrep;

import java.lang.reflect.Method;
import java.lang.annotation.Annotation;
import java.util.*;
import java.util.Map.Entry;
import java.util.stream.Collectors;

import com.github.jpleasu.ldggrep.internal.MethodInfo;

/**
 * processes and manages LDGGrep annotated methods
 */
public class MethodManager {
	final Object target;

	final Map<Class<? extends Annotation>, Map<String, BoundMethod>> methodMap;

	private final MethodInfo LITERAL_METHOD_INFO =
		new MethodInfo(StartGen.LITERAL, new String[] { "literal" }, "a literal");
	private final MethodInfo REGEX_METHOD_INFO =
		new MethodInfo(StartGen.REGEX, new String[] { "pattern" }, "a regex");

	public MethodManager(Object target) {
		this.target = target;
		methodMap = new HashMap<>();
		methodMap.put(NPred.class, new HashMap<>());
		methodMap.put(EPred.class, new HashMap<>());
		Class<?> clazz = target.getClass();

		while (clazz != null) {
			for (final Method method : clazz.getDeclaredMethods()) {
				for (Entry<Class<? extends Annotation>, Map<String, BoundMethod>> e : methodMap
						.entrySet()) {
					Class<? extends Annotation> annClass = e.getKey();
					Map<String, BoundMethod> map = e.getValue();

					if (method.isAnnotationPresent(annClass)) {
						Annotation ann = method.getAnnotation(annClass);

						MethodInfo xpred = new MethodInfo(ann);
						map.putIfAbsent(xpred.getName(method.getName()),
							new BoundMethod(target, method, xpred));
					}
				}
			}
			clazz = clazz.getSuperclass();
		}

		clazz = target.getClass();
		Map<String, BoundMethod> startGenMap = new HashMap<>();
		while (clazz != null) {
			// take another pass looking for StartGen methods. use exist NPred to populate info
			for (final Method method : clazz.getDeclaredMethods()) {
				if (method.isAnnotationPresent(StartGen.class)) {
					StartGen ann = method.getAnnotation(StartGen.class);
					BoundMethod npredMethod = methodMap.get(NPred.class).get(ann.value());
					if (npredMethod != null) {
						startGenMap.put(ann.value(),
							new BoundMethod(target, method, npredMethod.info));
					}
					else { // regex or literal
						if (StartGen.LITERAL.equals(ann.value())) {
							startGenMap.putIfAbsent(StartGen.LITERAL,
								new BoundMethod(target, method, LITERAL_METHOD_INFO));
						}
						else if (StartGen.REGEX.equals(ann.value())) {
							startGenMap.putIfAbsent(StartGen.REGEX,
								new BoundMethod(target, method, REGEX_METHOD_INFO));
						}
						else {
							throw new RuntimeException(
								"StartGen with unmatched node predicate: " + ann.value());
						}
					}
				}
			}

			clazz = clazz.getSuperclass();
		}
		methodMap.put(StartGen.class, startGenMap);
	}

	public void clear() {
		methodMap.clear();
	}

	@FunctionalInterface
	public interface PredEnumerator {
		void apply(String prototype, String description);
	}

	public void forEachPred(Class<? extends Annotation> ann, PredEnumerator pe) {
		Map<String, BoundMethod> map = methodMap.getOrDefault(ann, Collections.emptyMap());
		for (Entry<String, BoundMethod> e : map.entrySet()) {
			BoundMethod m = e.getValue();
			String predicateName = e.getKey();
			String args;
			if (m.info.args != null && m.info.args.length > 0) {
				args = '(' + Arrays.stream(m.info.args).collect(Collectors.joining(",")) + ')';
			}
			else {
				args = "";
			}
			pe.apply(predicateName + args, m.info.description);
		}
	}

	public Map<String, BoundMethod> getMethodMap(Class<? extends Annotation> ann) {
		return methodMap.get(ann);
	}
}
