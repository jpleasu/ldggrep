package com.github.jpleasu.ldggrep.ghidra;

import java.util.ArrayList;
import java.util.List;

import com.github.jpleasu.ldggrep.ghidra.util.AddressDelegate;

import ghidra.program.model.block.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * A wrapper to represent CodeBlock objects as Addresses.
 */
public class BlockAddress extends AddressDelegate {
	public final CodeBlock codeBlock;

	public BlockAddress(CodeBlock cb) {
		super(cb.getMaxAddress()); // use an address very unlikely to be used by RefGrep to avoid bad merging results.
		this.codeBlock = cb;
	}

	public CodeBlock getCallDest(TaskMonitor monitor) {
		try {
			CodeBlockReferenceIterator cbit = codeBlock.getDestinations(monitor);
			while (cbit.hasNext()) {
				CodeBlockReference r = cbit.next();
				if (r.getFlowType().isCall()) {
					return r.getDestinationBlock();
				}
			}
		}
		catch (CancelledException e) {
			e.printStackTrace();
		}
		return null;
	}

	public List<CodeBlock> getNonCallDests(TaskMonitor monitor) {
		List<CodeBlock> l = new ArrayList<>();
		try {
			CodeBlockReferenceIterator cbit = codeBlock.getDestinations(monitor);
			while (cbit.hasNext()) {
				CodeBlockReference r = cbit.next();
				if (!r.getFlowType().isCall()) {
					l.add(r.getDestinationBlock());
				}
			}
		}
		catch (CancelledException e) {
			e.printStackTrace();
		}
		return l;
	}

	@Override
	public boolean equals(Object o) {
		return (o instanceof BlockAddress) && super.equals(o);
	}
}