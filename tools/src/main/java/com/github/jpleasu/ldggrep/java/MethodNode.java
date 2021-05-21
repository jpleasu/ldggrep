package com.github.jpleasu.ldggrep.java;

public class MethodNode extends Node {
	final ClassNode cl;
	final String name;

	public MethodNode(ClassNode cl, String methname) {
		this.cl = cl;
		this.name = methname;
	}

	@Override
	public String toString() {
		return String.format("%s::%s", cl.name, name);
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((cl == null) ? 0 : cl.hashCode());
		result = prime * result + ((name == null) ? 0 : name.hashCode());
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
		MethodNode other = (MethodNode) obj;
		if (cl == null) {
			if (other.cl != null)
				return false;
		}
		else if (!cl.equals(other.cl))
			return false;
		if (name == null) {
			if (other.name != null)
				return false;
		}
		else if (!name.equals(other.name))
			return false;
		return true;
	}

}
