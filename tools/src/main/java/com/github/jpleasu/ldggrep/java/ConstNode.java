package com.github.jpleasu.ldggrep.java;

public class ConstNode extends Node {
	final String strRepr;

	ConstNode(Object v) {
		if (v == null)
			strRepr = "null";
		else if (v instanceof String)
			strRepr = String.format("\"%s\"", v);
		else if (v instanceof Number)
			strRepr = String.format("%s", v);
		else
			strRepr = String.format("(%s)%s", v.getClass().getName(), v.toString());
	}

	@Override
	public String toString() {
		return strRepr;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((strRepr == null) ? 0 : strRepr.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		ConstNode other = (ConstNode) obj;
		if (strRepr == null) {
			if (other.strRepr != null)
				return false;
		}
		else if (!strRepr.equals(other.strRepr))
			return false;
		return true;
	}

}
