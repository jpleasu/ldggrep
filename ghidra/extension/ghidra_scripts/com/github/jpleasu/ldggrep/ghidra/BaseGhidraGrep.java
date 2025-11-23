package com.github.jpleasu.ldggrep.ghidra;

import java.io.*;
import java.util.*;
import java.util.Map.Entry;

import com.github.jpleasu.ldggrep.*;
import com.github.jpleasu.ldggrep.ghidra.gui.*;
import com.github.jpleasu.ldggrep.parser.Expr;
import com.github.jpleasu.ldggrep.parser_generated.ParseException;
import com.github.jpleasu.ldggrep.util.Pair;
import com.github.jpleasu.ldggrep.util.ReflectionUtil;

import generic.jar.ResourceFile;
import ghidra.app.plugin.core.table.TableComponentProvider;
import ghidra.app.script.GhidraScript;
import ghidra.app.services.GraphDisplayBroker;
import ghidra.app.util.query.TableService;
import ghidra.framework.Application;
import ghidra.framework.GModule;
import ghidra.framework.plugintool.PluginTool;
import ghidra.graph.visualization.DefaultGraphDisplayWrapper;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Program;
import ghidra.service.graph.*;
import ghidra.util.Msg;
import ghidra.util.SystemUtilities;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import utility.application.ApplicationLayout;

abstract public class BaseGhidraGrep<N, E> extends GhidraScript {
	abstract protected LDG<N, E> newLDG();

	abstract protected LDGModel<N, E> newModel();

	protected LDGMatcher<N, E> newMatcher(LDGModel<N, E> model, Expr expr) {

		model.initializeCodeContext(new OutputStream() {

			@Override
			public void write(int b) throws IOException {
				print(String.valueOf((char) b));
			}

			@Override
			public void write(byte b[], int off, int len) throws IOException {
				print((new String(b)).substring(off, off + len));
			}
		}, new OutputStream() {

			@Override
			public void write(int b) throws IOException {
				printerr(String.valueOf((char) b));
			}

			@Override
			public void write(byte b[], int off, int len) throws IOException {
				printerr((new String(b)).substring(off, off + len));
			}
		});

		LDGMatcher<N, E> matcher = new LDGMatcher<>(model, expr);

		Program program = getCurrentProgram();
		model.bind("p", program);
		model.bind("fm", program.getFunctionManager());
		model.bind("st", program.getSymbolTable());
		model.bind("li", program.getListing());
		model.bind("rm", program.getReferenceManager());
		model.bind("_matcher", matcher);
		model.bind("_model", model);

		model.bind("n2s", model.eval("(function(x) {return _model.nodeToString(x);})"));
		model.bind("e2s", model.eval("(function(x) {return _model.edgeToString(x);})"));
		model.bind("s", this);

		return matcher;
	}

	abstract public Address nodeToAddress(N n);

	abstract public Address edgeToAddress(E r);

	@SuppressWarnings("rawtypes")
	private static Map<Class<?>, Map<Program, LDG>> modelCache = new HashMap<>();

	protected File getHistorySavePath(Program program) {
		File projdir = getProjectRootFolder().getProjectLocator().getProjectDir();
		File f = new File(new File(projdir, "ldggrep"), String.format("%s-%s-%s.txt",
				this.getClass().getSimpleName(), program.getName(), program.getUniqueProgramID()));
		return f;
	}

	public void addToSelection(AddressSet addrs, Set<Pair<Integer, N>> ps) {
		for (Pair<Integer, N> p : ps) {
			addrs.add(nodeToAddress(p.getRight()));
		}
	}

	@SuppressWarnings({ "unchecked", "rawtypes" })
	private LDG<N, E> getCachedLDG() {
		Map<Program, LDG> cmodel_cache = modelCache.computeIfAbsent(getClass(), c -> new HashMap<>());
		return cmodel_cache.computeIfAbsent(currentProgram, (p) -> {
			printf("Computing new " + getClass().getName() + " LDG for program %s\n", p.getName());
			return newLDG();
		});
	}

	static Map<Class<?>, Map<Program, LDGGrepHistory>> queryHistories = new HashMap<>();

	private void dumpParseException(String expr_string, ParseException e) {
		printf("Parse exception:\n");
		printf("%s\n", e);
		printf("%s\n", expr_string);
		if (e.currentToken != null) {
			StringBuffer sb = new StringBuffer();
			for (int i = 0; i < e.currentToken.endColumn; ++i)
				sb.append(' ');
			printf("%s^-- here\n", sb.toString());
		}
	}

	private void ensureModule() {
		if (SystemUtilities.isInDevelopmentMode() &&
				Application.getModuleRootDir("LDGGrep") == null) {
			Application app = ReflectionUtil.getField(Application.class, null, "app");
			ApplicationLayout layout = ReflectionUtil.getField(app, "layout");
			ResourceFile moduleRoot = getSourceFile().getParentFile().getParentFile();
			Map<String, GModule> m = ReflectionUtil.getField(layout.getModules(), "m");
			m.put("LDGGrep", new GModule(Collections.emptyList(), moduleRoot));
		}
	}

	@Override
	protected void run() throws Exception {
		ensureModule();

		monitor.setProgress(0);
		monitor.setMaximum(4);

		monitor.setMessage("Constructing LDG...");
		LDGModel<N, E> model = newModel();
		LDG<N, E> graph = getCachedLDG();

		monitor.setProgress(1);
		monitor.setMessage("Waiting for query...");

		LDGGrepHistory qhist = queryHistories.computeIfAbsent(getClass(), c -> new HashMap<>())
				.computeIfAbsent(currentProgram,
						p -> new LDGGrepHistory(getHistorySavePath(currentProgram)));

		LDGGrepDialog<N, E> dialog = new LDGGrepDialog<>(this, model, qhist);
		if (dialog.isCanceled()) {
			throw new CancelledException();
		}
		String expr_string = dialog.getValueAsString();

		if (expr_string == null)
			return;

		printf("query: %s\n", expr_string);

		monitor.setProgress(2);
		monitor.setMessage("Computing match...");

		List<Expr> el;
		try {
			el = Expr.parseList(expr_string);
		} catch (ParseException e) {
			dumpParseException(expr_string, e);
			return;
		}

		// compute the match
		LDGMatch<N, E> match = null;
		final Map<Integer, Set<N>> memory = new HashMap<>();
		try {
			for (Expr expr : el) {
				LDGMatcher<N, E> matcher = newMatcher(model, expr);
				model.setIncomingMemory(memory);
				match = matcher.match(graph);
				if (match == null) {
					printf("No match\n");
					return;
				}
				memory.putAll(match.memory);
			}
		} catch (RuntimeException e) {
			if (e.getCause() instanceof ParseException) {
				ParseException ec = (ParseException) e.getCause();
				dumpParseException(expr_string, ec);
				return;
			}
			throw e;
		}

		monitor.setProgress(3);
		monitor.setMessage("Rendering result...");

		if (dialog.show_stomem) {
			PluginTool tool = getState().getTool();
			Runnable runnable = () -> {
				TableService ts = tool.getService(TableService.class);

				MemoryTableModel tablemodel = new MemoryTableModel(tool, currentProgram) {
					@Override
					protected void doLoad(Accumulator<MemoryTableRow> accumulator, TaskMonitor mon)
							throws CancelledException {
						for (Entry<Integer, Set<N>> e : memory.entrySet())
							for (N n : e.getValue())
								accumulator.add(new MemoryTableRow(e.getKey(), nodeToAddress(n),
										model.nodeToString(n)));
					}

				};

				String n = this.getClass().getName() + " results for " + currentProgram.getName();
				TableComponentProvider<MemoryTableRow> tableProvider = ts.showTable(n, n, tablemodel, n, null);
				tableProvider.installRemoveItemsAction();
				tableProvider.setSubTitle(expr_string);
			};

			SystemUtilities.runSwingLater(runnable);
		}
		if (dialog.show_graph) {
			// semicolon suppresses graphing
			if (expr_string.endsWith(";"))
				return;

			PluginTool tool = state.getTool();

			GraphDisplayBroker graphDisplayBroker = tool.getService(GraphDisplayBroker.class);

			if (graphDisplayBroker == null) {
				Msg.showError(this, tool.getToolFrame(), "LDGGrep Error",
						"No graph display providers found: Please add a graph display provider to your tool");
				return;
			}

			GraphDisplayProvider displayProvider = graphDisplayBroker.getDefaultGraphDisplayProvider();

			GraphDisplay graphDisplay = displayProvider.getGraphDisplay(false, monitor);
			if (graphDisplay instanceof DefaultGraphDisplayWrapper) {
				GhidraJgtGraphViewer<N, E> graphViewer = new GhidraJgtGraphViewer<>(this, model,
						match, (DefaultGraphDisplayWrapper) graphDisplay);
				monitor.setProgress(3);

				printf("graph size: %d\n", graphViewer.getGraphSize());
				graphViewer.show();
			} else {
				Msg.showError(this, null, "Incompatible GraphDisplay",
						"The default graph provider is incompatible with this version of LDGGrep");
			}

		}
		monitor.setMessage("Done.");
		monitor.setProgress(4);
	}

}
