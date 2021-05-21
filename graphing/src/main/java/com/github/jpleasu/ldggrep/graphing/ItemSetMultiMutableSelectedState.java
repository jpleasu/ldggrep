package com.github.jpleasu.ldggrep.graphing;

import java.util.Set;

import org.jungrapht.visualization.selection.MultiMutableSelectedState;

public class ItemSetMultiMutableSelectedState<T> extends MultiMutableSelectedState<T> {
	@Override
	public boolean select(T element, boolean fireEvents) {
		return select(Set.of(element), fireEvents);
	}

	@Override
	public boolean deselect(T t, boolean fireEvents) {
		return deselect(Set.of(t), fireEvents);
	}
}
