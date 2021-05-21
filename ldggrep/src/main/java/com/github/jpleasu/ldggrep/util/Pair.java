package com.github.jpleasu.ldggrep.util;

public class Pair<L, R> {
	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((left == null) ? 0 : left.hashCode());
		result = prime * result + ((right == null) ? 0 : right.hashCode());
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
		Pair<?, ?> other = (Pair<?, ?>) obj;
		if (left == null) {
			if (other.left != null)
				return false;
		}
		else if (!left.equals(other.left))
			return false;
		if (right == null) {
			if (other.right != null)
				return false;
		}
		else if (!right.equals(other.right))
			return false;
		return true;
	}

	protected final L left;
	protected final R right;

	protected Pair(L left, R right) {
		this.left = left;
		this.right = right;
	}

	static public <L, R> Pair<L, R> of(L left, R right) {
		return new Pair<L, R>(left, right);
	}

	public L getLeft() {
		return left;
	}

	public R getRight() {
		return right;
	}

	@Override
	public String toString() {
		return "(" + left.toString() + "," + right.toString() + ")";
	}
}
