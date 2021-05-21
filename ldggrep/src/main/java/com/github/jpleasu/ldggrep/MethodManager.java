package com.github.jpleasu.ldggrep;

import java.lang.reflect.Method;
import java.lang.annotation.Annotation;
import java.util.*;
import java.util.Map.Entry;
import java.util.stream.Collectors;

import com.github.jpleasu.ldggrep.internal.XPred;

/**
 * processes LDGGrep predicate annotations from classes and provides binding routines
 */
public class MethodManager {
	final Object target;

	static class UnboundMethodMap {
		final Class<?> targetClass;
		final Map<String, Method> methods;

		UnboundMethodMap(Class<?> targetClass, Map<String, Method> methods) {
			this.targetClass = targetClass;
			this.methods = methods;
		}

		public Class<?> getTargetClass() {
			return targetClass;
		}

		public Method getMethod(String name) {
			return methods.get(name);
		}

	}

	final Map<Class<? extends Annotation>, List<UnboundMethodMap>> unboundMethodMapMap =
		new HashMap<>();

	public MethodManager(Object target) {
		this.target = target;

		Map<Class<? extends Annotation>, HashMap<String, Method>> mapByAnnotation = Map.of(
			NPred.class, new HashMap<String, Method>(), EPred.class, new HashMap<String, Method>());
		Class<?> clazz = target.getClass();

		while (clazz != null) {
			for (final Method m : clazz.getDeclaredMethods()) {
				for (Entry<Class<? extends Annotation>, HashMap<String, Method>> e : mapByAnnotation
						.entrySet()) {
					Class<? extends Annotation> annClass = e.getKey();

					if (m.isAnnotationPresent(annClass)) {
						Annotation ann = m.getAnnotation(annClass);
						XPred xpred = new XPred(ann);
						e.getValue().put(xpred.getName(m.getName()), m);
					}
				}
			}
			clazz = clazz.getSuperclass();
		}
		for (Entry<Class<? extends Annotation>, HashMap<String, Method>> e : mapByAnnotation
				.entrySet()) {
			unboundMethodMapMap.computeIfAbsent(e.getKey(), x -> new ArrayList<>())
					.add(new UnboundMethodMap(target.getClass(), e.getValue()));
		}
	}

	public void clear() {
		unboundMethodMapMap.clear();
	}

	@FunctionalInterface
	public interface PredEnumerator {
		void apply(String prototype, String description);
	}

	public void forEachPred(Class<? extends Annotation> ann, PredEnumerator pe) {
		for (UnboundMethodMap umm : unboundMethodMapMap.getOrDefault(ann,
			Collections.emptyList())) {
			for (Entry<String, Method> e : umm.methods.entrySet()) {
				Method m = e.getValue();
				String predicateName = e.getKey();
				XPred xpred = new XPred(m.getAnnotation(ann));
				String args;
				if (xpred.args.length > 0) {
					args = '(' + Arrays.stream(xpred.args).collect(Collectors.joining(",")) + ')';
				}
				else {
					args = "";
				}
				pe.apply(predicateName + args, xpred.description);
			}
		}
	}

	public static class BoundMethod {
		public final Object obj;
		public final Method method;

		public BoundMethod(Object obj, Method method) {
			this.obj = obj;
			this.method = method;
		}
	}

	/**
	 * find a previously added annotated method which binds to one of the given bindings.
	 * 
	 * If an unbound method exists with the given annotation and name, but there is no binding, null is returned.
	 * 
	 * @param ann EPred or NPred annotation type
	 * @param name from the annotation
	 * @return a bound method or null
	 */
	public BoundMethod find(Class<? extends Annotation> ann, String name) {
		List<UnboundMethodMap> unboundMethodMaps = unboundMethodMapMap.get(ann);
		if (unboundMethodMaps != null) {
			for (UnboundMethodMap unboundMethodMap : unboundMethodMaps) {
				Method method = unboundMethodMap.getMethod(name);
				if (method != null) {
					return new BoundMethod(target, method);
				}
			}
		}
		return null;
	}

	public void validateBindings(Map<Class<?>, Object> classBindings) {
		for (List<UnboundMethodMap> ubmml : unboundMethodMapMap.values()) {
			for (UnboundMethodMap ubmm : ubmml) {
				if (!classBindings.containsKey(ubmm.targetClass)) {
					throw new RuntimeException("no binding for " + ubmm.targetClass.toString());
				}
			}
		}
	}

}
