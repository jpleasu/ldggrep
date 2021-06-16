package com.github.jpleasu.ldggrep.internal;

import java.util.stream.Stream;

import com.github.jpleasu.ldggrep.LDG;

public interface Generator<N, E> {
	Stream<N> startNodes(LDG<N, E> graph);
}