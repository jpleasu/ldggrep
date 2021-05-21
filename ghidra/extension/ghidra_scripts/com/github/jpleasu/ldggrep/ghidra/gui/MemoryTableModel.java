package com.github.jpleasu.ldggrep.ghidra.gui;

import java.lang.reflect.Method;

import docking.widgets.table.AbstractDynamicTableColumn;
import docking.widgets.table.TableColumnDescriptor;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.table.AddressBasedTableModel;
import ghidra.util.task.TaskMonitor;

abstract public class MemoryTableModel extends AddressBasedTableModel<MemoryTableRow> {
	public MemoryTableModel(PluginTool tool, Program program) {
		super("mem", tool, program, null, false);
	}

	@SuppressWarnings({ "unchecked" })
	static <R> void addCol(TableColumnDescriptor<MemoryTableRow> descriptor, String colname,
			java.util.function.Function<MemoryTableRow, R> handler) {
		Class<R> colclass0 = null;
		for (Method m : handler.getClass().getDeclaredMethods()) {
			if (m.getName().equals("apply"))
				colclass0 = (Class<R>) m.getReturnType();
		}
		if (colclass0 == null) {
			throw new RuntimeException(String.format(
				"can't find return type of handler for column %s with reflection", colname));
		}

		final Class<R> colclass = colclass0;
		descriptor.addVisibleColumn(new AbstractDynamicTableColumn<MemoryTableRow, R, Program>() {
			@Override
			public String getColumnName() {
				return colname;
			}

			@Override
			public R getValue(MemoryTableRow rowObject, Settings settings, Program data,
					ServiceProvider serviceProvider) throws IllegalArgumentException {
				return handler.apply(rowObject);
			}

			/*
			@Override
			protected String doGetUniqueIdentifier() {
			  return getColumnName() + this.toString() + System.identityHashCode(this);
			}
			*/

			@Override
			public Class<R> getColumnClass() {
				return colclass;
			}

		});
	}

	@Override
	protected TableColumnDescriptor<MemoryTableRow> createTableColumnDescriptor() {
		TableColumnDescriptor<MemoryTableRow> d = new TableColumnDescriptor<>();
		addCol(d, "location", o -> o.a);
		addCol(d, "node name", o -> o.name);
		addCol(d, "sto/mem slot", o -> o.slot);
		return d;
	}

	@Override
	public Address getAddress(int row) {
		MemoryTableRow r = getRowObject(row);
		return r.a;
	}

	@Override
	abstract protected void doLoad(Accumulator<MemoryTableRow> accumulator, TaskMonitor monitor)
			throws CancelledException;
}
