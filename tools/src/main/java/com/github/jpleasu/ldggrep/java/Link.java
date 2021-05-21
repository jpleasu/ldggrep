package com.github.jpleasu.ldggrep.java;

public class Link<SrcClass extends Node, DstClass extends Node> {
	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((src == null) ? 0 : src.hashCode());
		result = prime * result + ((dst == null) ? 0 : dst.hashCode());
		return result;
	}

	@SuppressWarnings("rawtypes")
	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		Link other = (Link) obj;
		if (src == null) {
			if (other.src != null)
				return false;
		}
		else if (!src.equals(other.src))
			return false;
		if (dst == null) {
			if (other.dst != null)
				return false;
		}
		else if (!dst.equals(other.dst))
			return false;
		return true;
	}

	final SrcClass src;
	final DstClass dst;

	public Link(SrcClass d0, DstClass d1) {
		this.src = d0;
		this.dst = d1;
	}

	@Override
	public String toString() {
		return String.format("%s -> %s", src, dst);
	}
}
