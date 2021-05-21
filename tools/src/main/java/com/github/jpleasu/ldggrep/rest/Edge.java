package com.github.jpleasu.ldggrep.rest;

import com.google.gson.JsonElement;
import com.google.gson.annotations.Expose;

public class Edge {
	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((id == null) ? 0 : id.hashCode());
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
		Edge other = (Edge) obj;
		if (id == null) {
			if (other.id != null)
				return false;
		}
		else if (!id.equals(other.id))
			return false;
		return true;
	}

	@Expose
	public String id;
	@Expose
	public String srcid;
	@Expose
	public String dstid;
	@Expose
	public JsonElement props;

	public Node dst;
}