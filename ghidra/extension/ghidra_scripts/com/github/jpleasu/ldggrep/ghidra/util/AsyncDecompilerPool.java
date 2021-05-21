package com.github.jpleasu.ldggrep.ghidra.util;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

import generic.cache.CachingPool;
import generic.cache.CountingBasicFactory;
import generic.concurrent.GThreadPool;
import ghidra.app.decompiler.ClangTokenGroup;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.util.DecompilerConcurrentQ;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.util.task.TaskMonitor;

/**
 * Combination pool/work queue for decompilation
 */
public class AsyncDecompilerPool {
	public interface OnConfig {
		void apply(DecompInterface decompiler);
	}

	public interface Task {
		void apply(ClangTokenGroup docroot, HighFunction hfunc);
	}

	private class DecompilerFactory extends CountingBasicFactory<DecompInterface> {
		@Override
		public DecompInterface doCreate(int itemNumber) throws IOException {
			DecompInterface decompiler = new DecompInterface();
			decompiler.setOptions(options);
			if (onConfigFunc != null)
				onConfigFunc.apply(decompiler);
			decompiler.openProgram(program);
			return decompiler;
		}

		@Override
		public void doDispose(DecompInterface decompiler) {
			decompiler.dispose();
		}
	}

	private CachingPool<DecompInterface> decompilerPool;
	final private Map<Function, DecompileResults> fmap = new HashMap<>();
	private OnConfig onConfigFunc = null;
	final private DecompileOptions options;
	final private Program program;
	final private DecompilerConcurrentQ<Function, Integer> queue;
	final private Map<Function, List<Task>> tasks = new HashMap<>();
	final String threadPoolName;

	public AsyncDecompilerPool(Program program, DecompileOptions options, TaskMonitor monitor) {
		this.program = program;
		this.options = options;
		decompilerPool = new CachingPool<DecompInterface>(new DecompilerFactory());
		threadPoolName = "Async Decompiler ThreadPool";
		queue = new DecompilerConcurrentQ<Function, Integer>(this::work, threadPoolName, monitor);
	}

	public void addTask(Function func, Consumer<HighFunction> task) {
		addTask(func, (docroot, hf) -> task.accept(hf));
	}

	/** add a task to execute on the decompilation of func
	 *  
	 * @param func a function that will be decompiled 
	 * @param task the task to executed when {@code func} is decompiled
	 */
	public synchronized void addTask(Function func, Task task) {
		DecompileResults dr = fmap.get(func);
		if (dr != null) {
			task.apply(dr.getCCodeMarkup(), dr.getHighFunction());
			// XXX: if task is getting too large, age off old entries.
		}
		else {
			tasks.computeIfAbsent(func, f -> new ArrayList<>()).add(task);
			queue.add(func);
		}
	}

	public void dispose() {
		queue.dispose();
		decompilerPool.dispose();
	}

	public void onConfig(OnConfig oc) {
		onConfigFunc = oc;
	}

	public void setMaxThreadCount(int maxThreadCount) {
		GThreadPool tp = GThreadPool.getSharedThreadPool(threadPoolName);
		tp.setMaxThreadCount(maxThreadCount);
	}

	public void waitForResults() throws InterruptedException {
		queue.waitForResults();
	}

	// called when a thread becomes available and there are outstanding functions to decompile
	private int work(Function func, TaskMonitor mon) throws Exception {
		DecompileResults dr = null;
		DecompInterface di = decompilerPool.get();
		try {
			dr = di.decompileFunction(func, options.getDefaultTimeout(), mon);
		}
		finally {
			decompilerPool.release(di);
			synchronized (this) {
				fmap.put(func, dr);
				if (tasks.containsKey(func)) {
					List<Task> l = tasks.get(func);
					Iterator<Task> it = l.iterator();
					while (it.hasNext()) {
						Task t = it.next();
						it.remove();
						try {
							if (dr != null)
								t.apply(dr.getCCodeMarkup(), dr.getHighFunction());
						}
						catch (Throwable e) {
							System.err.printf("%s: task err: %s\n", this.getClass(), e);
							e.printStackTrace();
							throw new RuntimeException(e);
						}
					}
				}
			}
		}
		return 0;
	}
}
