//An LDGGrep model based on Address nodes and Ghidra Reference edges
//@category LDGGrep
//@keybinding ctrl 5
//@importpackage com.github.jpleasu.ldggrep

import com.github.jpleasu.ldggrep.LDG;
import com.github.jpleasu.ldggrep.ghidra.*;

import ghidra.program.model.address.Address;

public class RefGrep extends BaseGhidraGrep<Address, RefEdge> {

	@Override
	protected ReferenceGrepModel newModel() {
		return new ReferenceGrepModel(currentProgram);
	}

	@Override
	public Address nodeToAddress(Address n) {
		return n;
	}

	@Override
	public Address edgeToAddress(RefEdge e) {
		return e.r.getFromAddress();
	}

	@Override
	protected LDG<Address, RefEdge> newLDG() {
		return new ReferenceGrepGraph(currentProgram);
	}
}
