package com.github.jpleasu.ldggrep.ghidra;

import com.github.jpleasu.ldggrep.*;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.*;

public class ReferenceGrepModel extends LDGModel<Address, RefEdge> {
	@EPred
	boolean call(RefEdge e) {
		return e.r.getReferenceType().isCall();
	}

	@EPred
	boolean ref(RefEdge e) {
		return e.r.getReferenceType().isData();
	}

	@EPred(description = "read reference")
	boolean rref(RefEdge e) {
		RefType rt = e.r.getReferenceType();
		return rt.isData() && (rt.isRead() || param(e));
	}

	@EPred(description = "parameter reference -- passed as a parameter")
	boolean param(RefEdge e) {
		RefType rt = e.r.getReferenceType();
		return rt.getName() == "PARAM";
	}

	@EPred(description = "write reference")
	boolean wref(RefEdge e) {
		RefType rt = e.r.getReferenceType();
		return rt.isData() && rt.isWrite();
	}

	@NPred(description = "function")
	boolean func(Address a) {
		return fm.getFunctionAt(a) != null;
	}

	@NPred(description = "function that doesn't return")
	boolean noreturn(Address a) {
		Function f = fm.getFunctionAt(a);
		if (f != null)
			return f.hasNoReturn();
		return false;
	}

	@NPred(description = "global variable / memory address")
	boolean global(Address a) {
		return !func(a);
	}

	@NPred(description = "thunk or reference to thunked function")
	boolean thunk(Address addr) {
		Function f = fm.getFunctionAt(addr);
		if (f != null)
			return f.isThunk();
		return false;
	}

	@NPred(description = "external address")
	boolean ext(Address addr) {
		try {
			mm.getByte(addr);
			return false;
		}
		catch (MemoryAccessException e) {
			return true;
		}
	}

	@SuppressWarnings("deprecation")
	@NPred(description = "import")
	boolean imp(Address addr) {
		if (thunk(addr) && !ext(addr))
			return true;
		if (addr.isStackAddress() || addr.isRegisterAddress())
			return false;

		/*
		for (Reference r : rm.getReferencesTo(addr)) {
			RefType rt = r.r.getReferenceType();
			if (rt.isComputed() && rt.isCall() && r.isExternalReference())
				return true;
		}
		*/
		return false;
	}

	@NPred(description = "export")
	boolean exp(Address addr) {
		return st.isExternalEntryPoint(addr);
	}

	@NPred(description = "string")
	boolean str(Address addr) {
		Data dd = li.getDefinedDataAt(addr);
		if (dd != null) {
			DataType dt = dd.getDataType();
			if (dt instanceof StringDataType)
				return true;
			else if (dt.getName().equals("unicode"))
				return true;
		}
		return false;
	}

	protected final Program program;
	protected final FunctionManager fm;
	protected final SymbolTable st;
	protected final Listing li;
	protected final Memory mm;

	public ReferenceGrepModel(Program program) {
		this.program = program;
		fm = program.getFunctionManager();
		st = program.getSymbolTable();
		li = program.getListing();
		mm = program.getMemory();
	}

	// a helper for bracket expressions
	public String str(Object x) {
		if (x instanceof Address)
			return nodeToString((Address) x);
		else if (x instanceof RefEdge)
			return edgeToString((RefEdge) x);
		else if (x == null)
			return "(null)";
		return x.toString();
	}

	@Override
	public String edgeToString(RefEdge e) {
		if (call(e))
			return "call";
		else if (rref(e))
			return "rref";
		else if (wref(e))
			return "wref";
		return String.format("ref(%s)", e.r.getReferenceType().getName());
	}

	@Override
	public String nodeToString(Address addr) {
		Data dd = li.getDefinedDataAt(addr);
		String typedptr = null;
		if (dd != null) {
			DataType dt = dd.getDataType();
			String n = dt.getName();
			String v = dd.getDefaultValueRepresentation();
			if (dt instanceof StringDataType)
				return v;
			else if (n.equals("unicode"))
				return v; // u"blah"
			else if (!(dt instanceof Undefined) && !(dt instanceof Pointer))
				typedptr = String.format("(%s)%s", n, v);
		}
		Symbol s = st.getPrimarySymbol(addr);
		if (s != null)
			return s.getName(true);
		if (typedptr != null)
			return typedptr;
		return addr.toString();
	}

}