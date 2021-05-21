package com.github.jpleasu.ldggrep.util;

import java.lang.reflect.*;

public class ReflectionUtil {
	public static Method getMethod(Class<?> objClass, String methodName) {
		Class<?> clazz = objClass;
		while (clazz != null) {
			for (Method m : clazz.getDeclaredMethods()) {
				if (m.getName().equals(methodName)) {
					return m;
				}
			}
			clazz = clazz.getSuperclass();
		}
		return null;
	}

	@SuppressWarnings("unchecked")
	public static <ReturnT> ReturnT invoke(Object obj, String methodName, Object... args) {
		Method m = getMethod(obj.getClass(), methodName);
		if (m != null) {
			try {
				m.setAccessible(true);
				return (ReturnT) m.invoke(obj, args);
			}
			catch (IllegalAccessException | IllegalArgumentException
					| InvocationTargetException e) {
				e.printStackTrace();
			}
		}
		return null;
	}

	public static Field getFieldObject(Class<?> clazz, String fieldName) {
		while (clazz != null) {
			for (Field f : clazz.getDeclaredFields()) {
				if (f.getName().equals(fieldName)) {
					return f;
				}
			}
			clazz = clazz.getSuperclass();
		}
		return null;
	}

	@SuppressWarnings("unchecked")
	public static <T> T getField(Class<?> clazz, Object o, String fieldName) {
		Field f = getFieldObject(clazz, fieldName);
		if (f != null) {
			f.setAccessible(true);
			try {
				return (T) f.get(o);
			}
			catch (IllegalArgumentException | IllegalAccessException e) {
				e.printStackTrace();
				return null;
			}
		}
		return null;
	}

	public static <T> T getField(Object obj, String fieldName) {
		return getField(obj.getClass(), obj, fieldName);
	}

	// use for static fields
	public static <T> void setField(Class<?> clazz, Object obj, String fieldName, T newValue) {
		Field f = getFieldObject(clazz, fieldName);
		if (f != null) {
			f.setAccessible(true);
			try {
				f.set(obj, newValue);
				return;
			}
			catch (IllegalArgumentException | IllegalAccessException e) {
				e.printStackTrace();
			}
		}
	}

	public static <T> void setField(Object obj, String fieldName, T newValue) {
		setField(obj.getClass(), obj, fieldName, newValue);
	}
}
