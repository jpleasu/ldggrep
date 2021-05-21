//Example of an LDGGrep model that adds predicates to RefGrep
//@category LDGGrep
//@keybinding ctrl 7

import com.github.jpleasu.ldggrep.*;
import com.github.jpleasu.ldggrep.ghidra.*;
import com.github.jpleasu.ldggrep.parser.Expr;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;

public class RefGrepExt extends RefGrep {

	@Override
	protected LDGMatcher<Address, RefEdge> newMatcher(LDGModel<Address, RefEdge> model, Expr expr) {
		LDGMatcher<Address, RefEdge> matcher = super.newMatcher(model, expr);
		model.bind("strlen", (java.util.function.Function<String, Integer>) (s -> s.length()));
		return matcher;
	}

	@Override
	protected ReferenceGrepModel newModel() {
		return new ReferenceGrepModel(currentProgram) {

			@Override
			public String edgeToString(RefEdge e) {
				if (jumpref(e)) {
					return "jumpref";
				}
				return super.edgeToString(e);
			}

			@NPred(description = "address that disassembles to a PUSH instruction")
			boolean push(Address addr) {
				Instruction i = li.getInstructionAt(addr);
				return i != null && i.getMnemonicString().equals("PUSH");
			}

			@NPred(description = "big function!")
			boolean big(Address addr) {
				Function f = getFunctionAt(addr);
				if (f == null)
					return false;
				return f.getBody().getNumAddresses() > 100;
			}

			@EPred(description = "jump reference")
			boolean jumpref(RefEdge e) {
				return e.r.getReferenceType().isJump();
			}

			@NPred(description = "demo use of string argument S", args = { "S" })
			boolean takes_str(Address addr, String s) {
				printf("takes_str got: %s\n", s);
				return false;
			}

		};
	}
}
