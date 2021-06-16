//RefGrep with references to DataTypes
//@category LDGGrep
//@keybinding ctrl 5
//@importpackage com.github.jpleasu.ldggrep

import java.util.*;
import java.util.stream.Stream;

import com.github.jpleasu.ldggrep.*;
import com.github.jpleasu.ldggrep.ghidra.*;
import com.github.jpleasu.ldggrep.ghidra.util.*;

import ghidra.app.decompiler.*;
import ghidra.app.extension.datatype.finder.DecompilerReference;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;
import ghidra.util.task.TaskMonitor;

public class RefGrepWithTypes extends RefGrep {
	public static class FieldAddress extends AddressDelegate {
		final DataType dt;
		final String fieldName;

		public FieldAddress(DataType dt, String fieldName, Address a) {
			super(a);
			this.dt = dt;
			this.fieldName = fieldName != null ? fieldName : "(null)";
		}

		@Override
		public boolean equals(Object o) {
			if (!super.equals(o) || !(o instanceof FieldAddress))
				return false;
			FieldAddress other = (FieldAddress) o;
			return dt.equals(other.dt) && fieldName.equals(other.fieldName);
		}
	}

	public static class FieldRef extends RefEdge {
		public FieldRef(Address fromAddr, FieldAddress toAddr) {
			super(new MemReferenceImpl(fromAddr, toAddr, RefType.DATA, SourceType.USER_DEFINED, -1,
				false));
		}
	}

	public static class Model extends ReferenceGrepModel {
		public Model(Program program) {
			super(program);
		}

		@Override
		public String nodeToString(Address addr) {
			if (addr instanceof FieldAddress) {
				FieldAddress field = (FieldAddress) addr;
				return field.dt.getName() + "::" + field.fieldName;
			}
			return super.nodeToString(addr);
		}

		@Override
		public String edgeToString(RefEdge e) {
			if (e instanceof FieldRef) {
				return "field";
			}
			return super.edgeToString(e);
		}

		@NPred
		public boolean field(Address n) {
			return n instanceof FieldAddress;
		}

		@EPred
		public boolean field(RefEdge e) {
			return e instanceof FieldRef;
		}

	}

	public static class LDG extends ReferenceGrepGraph {
		protected final Map<Address, List<RefEdge>> extraOutEdges = new HashMap<>();
		protected final DecompInterface decompiler;
		protected final TaskMonitor monitor;

		public LDG(Program program, TaskMonitor monitor) {
			super(program);

			this.monitor = monitor;

			decompiler = new DecompInterface();
			decompiler.setOptions(new DecompileOptions());
			decompiler.openProgram(program);
			decompiler.toggleSyntaxTree(true);
			decompiler.toggleCCode(true);
			decompiler.setSimplificationStyle("decompile");
		}

		@Override
		public Stream<RefEdge> outEdges(Address sourceAddr) {
			Function f = fm.getFunctionAt(sourceAddr);
			if (f != null) {
				List<RefEdge> ee = extraOutEdges.get(sourceAddr);
				if (ee == null) {
					final List<RefEdge> nee = new ArrayList<>();
					ee = nee;
					extraOutEdges.put(sourceAddr, ee);
					DecompileResults results = decompiler.decompileFunction(f, 30, monitor);
					if (results != null) {
						ClangTokenGroup docroot = results.getCCodeMarkup();
						// for each ClangFieldToken in this function's decompilation,
						//   that's the field of a Structure with a sensible offset,
						//     create a FieldAddress and add a new FieldRef to it
						Util.tokenStream(docroot)
								.filter(ClangFieldToken.class::isInstance)
								.forEach(tok -> {
									ClangFieldToken fieldToken = (ClangFieldToken) tok;
									DataType dataType =
										DecompilerReference.getBaseType(fieldToken.getDataType());
									if (dataType instanceof Structure) {
										Structure structType = (Structure) dataType;
										int offset = fieldToken.getOffset();
										if (offset >= 0 && offset < structType.getLength()) {
											DataTypeComponent dtc =
												structType.getComponentAt(fieldToken.getOffset());
											Address addr = Util.getPCAddress(fieldToken);
											if (addr == null) {
												addr = sourceAddr;
											}
											FieldAddress fa = new FieldAddress(structType,
												dtc.getFieldName(), addr);
											nee.add(new FieldRef(addr, fa));
										}
									}
								});
					}
				}
				return Stream.concat(super.outEdges(sourceAddr), ee.stream());
			}
			return super.outEdges(sourceAddr);
		}

	}

	@Override
	protected Model newModel() {
		return new Model(currentProgram);
	}

	@Override
	protected LDG newLDG() {
		return new LDG(currentProgram, getMonitor());
	}

}
