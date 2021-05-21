package com.github.jpleasu.ldggrep.ghidra.gui;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

public class LDGGrepHistory {
	static final int MAX_DEPTH = 30;
	LinkedList<String> h = new LinkedList<>();
	final private File savePath;

	public LDGGrepHistory(File savePath) {
		this.savePath = savePath;
		load();
	}

	private void save() {
		if (savePath != null) {
			try {
				savePath.getParentFile().mkdirs();
				Files.write(savePath.toPath(), h, StandardOpenOption.WRITE,
					StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
			}
			catch (IOException e) {
				e.printStackTrace();
			}
		}
	}

	private void load() {
		if (savePath != null && savePath.exists()) {
			try {
				h.clear();
				h.addAll(Files.readAllLines(savePath.toPath()));
			}
			catch (IOException e) {
				e.printStackTrace();
			}
		}
	}

	List<String> asList() {
		return h;
	}

	/** add s to this history.. it if was already in there, move it to the top 
	* @param s a query expression
	*/
	public void add(String s) {
		int i = h.indexOf(s);
		if (i < 0) {
			h.addFirst(s);
			if (h.size() > MAX_DEPTH)
				h.removeLast();
		}
		else {
			if (i != 0) {
				Collections.swap(h, i, 0);
			}
		}
		save();
	}

	public void clear() {
		h.clear();
		save();
	}

	String topOrDefault(String d) {
		if (h.size() > 0)
			return h.peek();
		return d;
	}
}