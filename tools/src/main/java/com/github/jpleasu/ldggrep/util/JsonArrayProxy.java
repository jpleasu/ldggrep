package com.github.jpleasu.ldggrep.util;

import org.graalvm.polyglot.Value;
import org.graalvm.polyglot.proxy.ProxyArray;

import com.google.gson.JsonArray;

public class JsonArrayProxy implements ProxyArray {
	final JsonArray arr;

	public JsonArrayProxy(JsonArray arr) {
		this.arr = arr;
	}

	@Override
	public Object get(long index) {
		return JsonProxy.of(arr.get((int) index));
	}

	@Override
	public long getSize() {
		return arr.size();
	}

	@Override
	public void set(long index, Value value) {
		throw new RuntimeException("ProxyArray is immutable");
	}

}
