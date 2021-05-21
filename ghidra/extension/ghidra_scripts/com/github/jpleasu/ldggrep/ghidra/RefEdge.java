package com.github.jpleasu.ldggrep.ghidra;

import java.util.Objects;

import ghidra.program.model.symbol.Reference;

/** wrapper of Reference objects which implements hashCode */
public class RefEdge {
	public final ghidra.program.model.symbol.Reference r;

	public RefEdge(Reference r) {
		this.r = r;
	}

	@Override
	public int hashCode() {
		return Objects.hash(r.getFromAddress(), r.getToAddress(), r.getReferenceType());
	}

	@Override
	public boolean equals(Object obj) {
		if (obj instanceof RefEdge) {
			return r.equals(((RefEdge) obj).r);
		}
		return false;
	}

}