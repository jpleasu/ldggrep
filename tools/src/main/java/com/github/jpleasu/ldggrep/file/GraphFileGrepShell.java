/**
 * a flat file matcher
 */
package com.github.jpleasu.ldggrep.file;

import java.util.Map.Entry;

import org.jgrapht.nio.GraphImporter;

import com.github.jpleasu.ldggrep.*;

public class GraphFileGrepShell extends BaseLDGGrepShell<Node, Edge> {
	final String path;

	public GraphFileGrepShell(String path) {
		this.path = path;
	}

	static void usage() {
		System.err.println("Usage: fgrep  INFILE");
		System.err.println("  where the following formats are supported by jgrapht.io:");
		for (Entry<String, GraphImporter<Node, Edge>> e : GraphFileLDG.importers.entrySet()) {
			System.err.printf("    %s - %s\n", e.getKey(), e.getValue().getClass().getName());
		}
	}

	public static void main(String[] args) {
		if (args.length == 1) {
			String fname = args[0];
			if (GraphFileLDG.lookupImporter(fname) == null) {
				System.err.printf("No support found for given file\n");
				usage();
				System.exit(1);
			}

			GraphFileGrepShell shell = new GraphFileGrepShell(fname);
			shell.startREPL();
		}
		else {
			usage();
		}
	}

	@Override
	protected LDG<Node, Edge> newLDG() {
		return new GraphFileLDG(path);
	}

}
