package com.github.jpleasu.ldggrep.util;

import java.math.BigDecimal;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;

public class JsonProxy {
	public static Object of(JsonElement e) {
		if (e instanceof JsonPrimitive) {
			JsonPrimitive p = (JsonPrimitive) e;
			if (p.isString())
				return p.getAsString();
			else if (p.isBoolean()) {
				return p.getAsBoolean();
			}
			else if (p.isNumber()) {
				BigDecimal d = p.getAsBigDecimal();
				if (d.scale() > 0)
					return d.doubleValue();
				return d.longValue();
			}
		}
		else if (e instanceof JsonObject) {
			return new JsonObjectProxy((JsonObject) e);
		}
		else if (e instanceof JsonArray) {
			return new JsonArrayProxy((JsonArray) e);
		}
		return e;
	}
}
