package com.github.jpleasu.ldggrep.ghidra.util;

import java.awt.Desktop;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.*;
import java.util.stream.Collectors;

import javax.swing.event.HyperlinkEvent;

import generic.stl.Pair;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.pcode.*;
import ghidra.util.Msg;

public class Util {

	// adapted from Ghidra's GHelpHTMLEditorKit
	public static void browseExternalLink(HyperlinkEvent e) {
		String description = e.getDescription();
		if (!Desktop.isDesktopSupported()) {
			Msg.info(Util.class, "Unable to launch external browser for " + description);
			return;
		}

		try {
			//  use an external browser
			URI uri = e.getURL().toURI();
			Desktop.getDesktop().browse(uri);
		}
		catch (URISyntaxException | IOException e1) {
			Msg.error(Util.class, "Error browsing to external URL " + description, e1);
		}
	}

	public static boolean isGlobal(Varnode vn) {
		HighVariable hvn = vn.getHigh();
		if (vn.isAddress() && hvn != null && hvn instanceof HighGlobal)
			return true;
		for (PcodeOp op : Util.getDescendents(vn)) {
			if (op.getOpcode() == PcodeOp.PTRSUB) {
				Varnode a = op.getInput(0);
				if (a != vn && a.isConstant() && a.getOffset() == 0)
					return true;
			}
		}
		return false;
	}

	public static class VarnodeComparator implements Comparator<Varnode> {
		private VarnodeComparator() {
		}

		@Override
		public int compare(Varnode o1, Varnode o2) {
			return System.identityHashCode(o1) - System.identityHashCode(o2);
		}

		public static VarnodeComparator instance = new VarnodeComparator();

	}

	/** return all PcodeOps associated with a particular instruction Address 
	 * @param hfunc the function whose ops to enumerate 
	 * @return an iterable of ops from the given function
	 */
	public static Iterable<PcodeOpAST> getPcodeOps(final HighFunction hfunc) {
		return new Iterable<PcodeOpAST>() {

			@Override
			public Iterator<PcodeOpAST> iterator() {
				return hfunc.getPcodeOps();
			}
		};
	}

	/** return all PcodeOps associated with a particular instruction Address 
	 * @param hfunc the function whose ops to enumerate 
	 * @param address an address from {@code hfunc}
	 * @return an iterable of ops at the given address from the given function
	 */
	public static Iterable<PcodeOpAST> getPcodeOps(final HighFunction hfunc,
			final Address address) {
		return new Iterable<PcodeOpAST>() {

			@Override
			public Iterator<PcodeOpAST> iterator() {
				return hfunc.getPcodeOps(address);
			}
		};
	}

	/** iterator to all PcodeOps that take this as input 
	 * @param vn a varnode
	 * @return an iterable over descendents of {@code vn}
	 */
	public static Iterable<PcodeOp> getDescendents(final Varnode vn) {
		return new Iterable<PcodeOp>() {

			@Override
			public Iterator<PcodeOp> iterator() {
				return vn.getDescendants();
			}
		};
	}

	public static String vnToStrWithType(Map<Varnode, String> vnh, Varnode vn) {
		if (vn == null)
			return "null";

		if (vn.isConstant())
			return String.format("0x%x", vn.getOffset());

		String n = vnh.get(vn);
		if (n == null) {
			HighVariable h = vn.getHigh();
			if (h != null) {
				DataType dt = h.getDataType();
				if (dt != null) {
					vnh.put(vn, n = String.format("(%s)vn%d", vn.getHigh().getDataType().toString(),
						vnh.size()));
					return n;
				}
			}
			vnh.put(vn, n = String.format("vn%d", vnh.size()));
		}

		return n;
		// return String.format("%s:(%s,0x%x)", n, vn.getAddress()
		// .getAddressSpace().getName(), vn.getOffset());
	}

	public static String vnToStr(Map<Varnode, String> vnh, Varnode vn) {
		if (vn == null)
			return "null";

		if (vn.isConstant())
			return String.format("0x%x", vn.getOffset());

		String n = vnh.get(vn);
		if (n == null) {
			vnh.put(vn, n = String.format("vn%d", vnh.size()));
		}

		return n;
		// return String.format("%s:(%s,0x%x)", n, vn.getAddress()
		// .getAddressSpace().getName(), vn.getOffset());
	}

	public static String opToStr(Map<Varnode, String> vnh, PcodeOp op) {
		Varnode out = op.getOutput();
		Varnode[] in = op.getInputs();
		String args = String.join(", ",
			Arrays.stream(in).map(vn -> vnToStr(vnh, vn)).collect(Collectors.toList()));
		return String.format("%s=%s(%s)", vnToStr(vnh, out), op.getMnemonic(), args);
	}

	/** make an iterable from an iterator 
	 * @param i an iterator 
	 * @param <T> a type
	 * @return an iterable
	 */
	public static <T> Iterable<T> iter(final Iterator<T> i) {
		return new Iterable<T>() {

			@Override
			public Iterator<T> iterator() {
				return i;
			}
		};
	}

	public static <T1, T2> Pair<T1, T2> pair(T1 t1, T2 t2) {
		return new Pair<>(t1, t2);
	}

	static Set<Integer> fwdEps =
		new HashSet<>(Arrays.asList(PcodeOp.CAST, PcodeOp.COPY, PcodeOp.MULTIEQUAL));

	public static Collection<Varnode> fwdEpsClosure(Varnode vn) {
		return fwdEpsClosure(Collections.singleton(vn));
	}

	public static Collection<Varnode> fwdEpsClosure(Collection<Varnode> vns0) {
		Set<Varnode> vns = new TreeSet<>(VarnodeComparator.instance);
		Set<Varnode> front = new TreeSet<>(VarnodeComparator.instance);

		front.addAll(vns0);
		while (!front.isEmpty()) {
			Set<Varnode> newfront = new TreeSet<>(VarnodeComparator.instance);
			vns.addAll(front);
			for (Varnode vn1 : front)
				for (PcodeOp op : Util.getDescendents(vn1))
					if (fwdEps.contains(op.getOpcode()))
						newfront.add(op.getOutput());
			newfront.removeAll(vns);
			front = newfront;
		}
		return vns;
	}

}
