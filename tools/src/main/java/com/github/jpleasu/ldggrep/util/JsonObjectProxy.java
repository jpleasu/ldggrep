package com.github.jpleasu.ldggrep.util;

import org.graalvm.polyglot.Value;
import org.graalvm.polyglot.proxy.ProxyObject;

import com.google.gson.JsonObject;

public class JsonObjectProxy implements ProxyObject {
	final JsonObject obj;

	public JsonObjectProxy(JsonObject obj) {
		this.obj = obj;
	}

	@Override
	public Object getMember(String key) {
		return JsonProxy.of(obj.get(key));
	}

	@Override
	public Object getMemberKeys() {
		return obj.keySet().toArray(new String[0]);
	}

	@Override
	public boolean hasMember(String key) {
		return obj.has(key);
	}

	@Override
	public void putMember(String key, Value value) {
		throw new RuntimeException("ProxyObject is immutable");
	}

}
