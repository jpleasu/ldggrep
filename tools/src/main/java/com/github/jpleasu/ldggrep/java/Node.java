package com.github.jpleasu.ldggrep.java;

import java.util.ArrayList;
import java.util.Collection;

public class Node {
	final Collection<Link<? extends Node, ? extends Node>> outLinks = new ArrayList<>();
	final Collection<Link<? extends Node, ? extends Node>> inLinks = new ArrayList<>();
}
