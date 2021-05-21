package com.github.jpleasu.ldggrep.ghidra;

import java.util.Arrays;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

import com.github.jpleasu.ldggrep.LDG;

import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;

public class ReferenceGrepGraph implements LDG<Address, RefEdge> {
	final protected FunctionManager fm;
	final protected ReferenceManager rm;

	public ReferenceGrepGraph(Program program) {
		fm = program.getFunctionManager();
		rm = program.getReferenceManager();
	}

	@Override
	public Stream<RefEdge> outEdges(Address sourceAddr) {
		Function f = fm.getFunctionAt(sourceAddr);
		AddressSetView fromSet = null;
		if (f != null) {
			fromSet = f.getBody();
		}
		else {
			fromSet = new AddressSet(sourceAddr);
		}

		return StreamSupport
				.stream(rm.getReferenceSourceIterator(fromSet, true).spliterator(), false)
				.flatMap(a0 -> {
					return Arrays.stream(rm.getReferencesFrom(a0)).filter(r -> {
						RefType typ = r.getReferenceType();
						return typ.isCall() || typ.isData();
					});
				})
				.map(RefEdge::new);
	}

	@Override
	public Address targetNode(RefEdge e) {
		return e.r.getToAddress();
	}

	@Override
	public Stream<Address> startNodes() {
		return StreamSupport.stream(fm.getFunctions(true).spliterator(), false)
				.map(Function::getEntryPoint);
	}
}