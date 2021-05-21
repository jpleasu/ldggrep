//An LDGGrep model with basic block nodes and edges
//@category LDGGrep
//@keybinding ctrl 6

import java.util.*;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

import com.github.jpleasu.ldggrep.*;
import com.github.jpleasu.ldggrep.ghidra.*;
import com.github.jpleasu.ldggrep.util.Pair;

import ghidra.app.services.BlockModelService;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.block.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.CancelledException;

/* the old hack that projected predicate machine state to addreses has been removed.. not sure why it was there..
 */
public class BlockGrep extends RefGrep {
	static public class BlockRefEdge extends RefEdge {
		public BlockRefEdge(Address fromAddr, Address toAddr) {
			super(new MemReferenceImpl(fromAddr, toAddr, RefType.CONDITIONAL_JUMP,
				SourceType.USER_DEFINED, -1, false));
		}
	}

	@Override
	public void addToSelection(AddressSet addrs, Set<Pair<Integer, Address>> ps) {
		for (Pair<Integer, Address> p : ps) {
			Address addr = p.getRight();
			if (addr instanceof BlockAddress) {
				addrs.add(((BlockAddress) addr).codeBlock);
			}
			else {
				addrs.add(addr);
			}
		}
	}

	// note: Ghidra's block model is not an LDGGrep graph model.
	SimpleBlockModel bm;

	@Override
	protected void run() throws Exception {
		BlockModelService bmserv = getState().getTool().getService(BlockModelService.class);
		CodeBlockModel bm0 = bmserv.getActiveBlockModel(currentProgram, true);
		if (!(bm0 instanceof SimpleBlockModel)) {
			printf("block model is %s, not simple\n", bm0.getClass().getName());
		}
		bm = (SimpleBlockModel) bm0;
		super.run();
	}

	@Override
	protected ReferenceGrepModel newModel() {
		// create an anonymous inner class
		return new ReferenceGrepModel(currentProgram) {

			@NPred(description = "block address (versus function or data address)")
			boolean block(Address a) {
				return a instanceof BlockAddress;
			}

			@EPred(description = "block transition")
			boolean block(RefEdge e) {
				return e instanceof BlockRefEdge;
			}

			@NPred(description = "call statement", args = { "FUNCTION_NAME" })
			boolean calls(Address a, String funcname) {
				if (a instanceof BlockAddress) {
					BlockAddress sa = (BlockAddress) a;
					CodeBlock cb = sa.getCallDest(monitor);
					if (cb != null) {
						return funcname.equals(nodeToString(cb.getMinAddress()));
					}
				}
				return false;
			}

			@NPred(description = "terminal block")
			boolean term(Address a) {
				if (a instanceof BlockAddress) {
					return ((BlockAddress) a).codeBlock.getFlowType().isTerminal();
				}
				return false;
			}

			@Override
			public String nodeToString(Address addr) {
				if (addr instanceof BlockAddress) {
					BlockAddress sa = (BlockAddress) addr;
					CodeBlock cb = sa.getCallDest(monitor);
					if (cb != null)
						return String.format("calls:%s", nodeToString(cb.getMinAddress()));
				}
				return super.nodeToString(addr);
			}

			@Override
			public String edgeToString(RefEdge e) {
				if (e instanceof BlockRefEdge)
					return "block";
				return super.edgeToString(e);
			}
		};
	}

	static class CBI implements Iterator<CodeBlock> {

		private final CodeBlockIterator cbi;

		CBI(CodeBlockIterator cbi) {
			this.cbi = cbi;
		}

		@Override
		public boolean hasNext() {
			try {
				return cbi.hasNext();
			}
			catch (CancelledException e) {
				return false;
			}
		}

		@Override
		public CodeBlock next() {
			try {
				return cbi.next();
			}
			catch (CancelledException e) {
				return null;
			}
		}

	}

	@Override
	protected LDG<Address, RefEdge> newLDG() {
		return new ReferenceGrepGraph(currentProgram) {
			@Override
			public Stream<Address> startNodes() {
				Iterable<CodeBlock> iterable = () -> {
					try {
						return new CBI(bm.getCodeBlocks(monitor));
					}
					catch (CancelledException e) {
						e.printStackTrace();
						return null;
					}
				};
				return Stream.concat(super.startNodes(),
					StreamSupport.stream(iterable.spliterator(), true).map(BlockAddress::new));
			}

			@Override
			public Stream<RefEdge> outEdges(Address a) {
				Stream<RefEdge> retstream;
				if (a instanceof BlockAddress) {
					BlockAddress sa = (BlockAddress) a;
					retstream = sa.getNonCallDests(monitor)
							.stream()
							.map(cb -> new BlockRefEdge(a, new BlockAddress(cb)));

					if (sa.codeBlock.getFlowType().isCall()) {
						Instruction i = currentProgram.getListing()
								.getInstructionContaining(sa.codeBlock.getMaxAddress());
						retstream = Stream.concat(retstream,
							Arrays.stream(getReferencesFrom(i.getAddress())).map(RefEdge::new));
					}
				}
				else {
					retstream = super.outEdges(a);
					try {
						Function f = getFunctionAt(a);
						if (f != null) {
							retstream = Stream.concat(retstream,
								Arrays.stream(bm.getCodeBlocksContaining(a, monitor))
										.map(cb -> new BlockRefEdge(a, new BlockAddress(cb))));
						}
					}
					catch (CancelledException e) {
						e.printStackTrace();
					}
				}
				return retstream;
			}
		};
	}

}
