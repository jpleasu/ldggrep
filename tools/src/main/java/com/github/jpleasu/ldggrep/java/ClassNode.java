package com.github.jpleasu.ldggrep.java;

public class ClassNode extends Node {

	final String name;

	ClassNode(String classname) {
		if (classname == null) {
			this.name = "null";
		}
		else {
			this.name = classname.replace('/', '.');
		}
	}

	@Override
	public String toString() {
		return String.format("class %s", name);
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
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
		ClassNode other = (ClassNode) obj;
		if (name == null) {
			if (other.name != null)
				return false;
		}
		else if (!name.equals(other.name))
			return false;
		return true;
	}

}
