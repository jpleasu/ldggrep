package com.github.jpleasu.ldggrep.internal;

import static org.junit.jupiter.api.Assertions.*;

import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;

import org.graalvm.polyglot.Context;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.github.jpleasu.ldggrep.*;
import com.github.jpleasu.ldggrep.parser.*;

public class TestGeneratorBuilder {

	public class TestClass {
		@NPred
		boolean is_x(String node) {
			return "x".equals(node);
		}

		@StartGen("is_x")
		Stream<String> generate_x(LDG<String, String> g) {
			return Stream.of("x");
		}

		@NPred(args = { "n" })
		boolean is_xrep(int state, String node, int n) {
			return "x".repeat(n).equals(node);
		}

		@StartGen("is_xrep")
		Stream<String> generate_y(LDG<String, String> g, int n) {
			return Stream.of("x".repeat(n));
		}

		@StartGen(StartGen.REGEX)
		Stream<String> generateRegex(LDG<String, String> g, String pat) {
			return Stream.of(pat);
		}

		@StartGen(StartGen.LITERAL)
		Stream<String> generateLiteral(LDG<String, String> g, String lit) {
			return Stream.of(lit);
		}

	}

	TestClass obj;
	MethodManager mm;
	Context jsctx;

	GeneratorBuilder<String, String> generatorBuilder;

	@BeforeEach()
	public void setup() {
		obj = new TestClass();
		mm = new MethodManager(obj);
		generatorBuilder = new GeneratorBuilder<String, String>(mm.getMethodMap(StartGen.class));
	}

	@Test
	public void test_any_pred() {
		Generator<String, String> g = generatorBuilder.buildGen(new AnyPred());
		assertNull(g);
	}

	@Test
	public void test_not_pred() {
		Generator<String, String> g = generatorBuilder.buildGen(new NotPred(new AnyPred()));
		assertNull(g);
	}

	@Test
	public void test_bare_pred() {
		Generator<String, String> g = generatorBuilder.buildGen(new BarePred("is_x", null));
		assertNotNull(g);
		Optional<String> first = g.startNodes(null).findFirst();
		assertTrue(first.isPresent());
		assertEquals("x", first.get());
	}

	@Test
	public void test_bare_pred_with_arg() {
		Generator<String, String> g =
			generatorBuilder.buildGen(new BarePred("is_xrep", List.of(3)));
		assertNotNull(g);
		Optional<String> first = g.startNodes(null).findFirst();
		assertTrue(first.isPresent());
		assertEquals("xxx", first.get());
	}

	@Test
	public void test_literal_pred() {
		Generator<String, String> g = generatorBuilder.buildGen(new LiteralPred("blah lit"));
		assertNotNull(g);
		Optional<String> first = g.startNodes(null).findFirst();
		assertTrue(first.isPresent());
		assertEquals("blah lit", first.get());
	}

	@Test
	public void test_regex_pred() {
		Generator<String, String> g = generatorBuilder.buildGen(new RegexPred("blah pat"));
		assertNotNull(g);
		Optional<String> first = g.startNodes(null).findFirst();
		assertTrue(first.isPresent());
		assertEquals("blah pat", first.get());
	}

}
