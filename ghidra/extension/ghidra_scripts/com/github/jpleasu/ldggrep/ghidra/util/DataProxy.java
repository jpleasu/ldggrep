package com.github.jpleasu.ldggrep.ghidra.util;

import java.util.ArrayList;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.mem.MemoryAccessException;

/**
 * a proxy to typed data to make accessing it a little more fluent in scripts.
 */
public class DataProxy {
	public final Data d;

	public DataProxy(Data d) {
		this.d = d;
	}

	public static DataProxy of(Data d) {
		return new DataProxy(d);
	}

	public Integer as_integer() {
		try {
			return d.getInt(0);
		}
		catch (MemoryAccessException e) {
			return null;
		}
	}

	public Address as_address() {
		return (Address) d.getValue();
	}

	/** assuming this field is a pointer to a (typed) memory address
	 *  
	 * @return the dereferenced proxy object
	 */
	public DataProxy deref() {
		Data fd = d.getMemory().getProgram().getListing().getDataAt(as_address());
		if (fd != null)
			return DataProxy.of(fd);
		return null;
	}

	public DataProxy getField(String fieldNamePat) {
		for (int ci = 0; ci < d.getNumComponents(); ++ci) {
			Data c = d.getComponent(ci);
			if (c.getFieldName().matches(fieldNamePat))
				return DataProxy.of(c);
		}
		return null;
	}

	public DataProxy[] as_array() {
		if (d.isArray()) {
			ArrayList<DataProxy> al = new ArrayList<>();
			for (int ai = 0; ai < d.getNumComponents(); ++ai)
				al.add(DataProxy.of(d.getComponent(ai)));
			return al.toArray(new DataProxy[0]);
		}
		return null;
	}

	public DataProxy[] force_array() {
		final DataProxy[] a = as_array();
		if (a == null)
			return new DataProxy[] { this };
		return a;
	}

	@Override
	public String toString() {
		StringBuffer sb = new StringBuffer();
		sb.append(String.format("(%s) %s : \n", d.getDataType().getName(), d.getAddress()));
		for (int ci = 0; ci < d.getNumComponents(); ++ci) {
			Data c = d.getComponent(ci);
			sb.append(String.format("  %s : %s\n", c.getFieldName(), c.getValue()));
		}
		return sb.toString();
	}

}
