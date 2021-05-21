package com.github.jpleasu.ldggrep.ghidra.gui;

import ghidra.program.model.address.Address;

public class MemoryTableRow {
	final int slot;
	final Address a;
	final String name;

	public MemoryTableRow(int slot, Address a, String name) {
		this.slot = slot;
		this.a = a;
		this.name = name;
	}

}