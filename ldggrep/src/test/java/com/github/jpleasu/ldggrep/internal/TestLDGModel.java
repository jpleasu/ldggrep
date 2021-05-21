package com.github.jpleasu.ldggrep.internal;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

import com.github.jpleasu.ldggrep.*;
import com.github.jpleasu.ldggrep.parser.*;

public class TestLDGModel {
	public static class TestModel extends LDGModel<String, Integer> {
		@NPred
		public boolean isa(String n) {
			return "a".equals(n);
		}
	}

	@Test
	void test_literal() {
		TestModel model = new TestModel();

		Pred<String> np = model.buildNodePred(new LiteralPred("a"));
		assertNotNull(np);
		assertTrue(np.matches(0, "a"));
		assertFalse(np.matches(0, "b"));

		Pred<Integer> ep = model.buildEdgePred(new LiteralPred("1"));
		assertNotNull(ep);
		assertTrue(ep.matches(0, 1));
		assertFalse(ep.matches(0, 2));
	}

	@Test
	void test_code_uninitialized_js() {
		TestModel model = new TestModel();

		RuntimeException e = assertThrows(RuntimeException.class, () -> {
			model.buildNodePred(new CodePred("x=='a'"));
		});
		assertEquals("must set code context before building code predicates", e.getMessage());

	}

	@Test
	void test_code_basic_operation() {
		TestModel model = new TestModel();
		model.initializeCodeContext();

		Pred<String> np = model.buildNodePred(new CodePred("x=='a'"));
		assertNotNull(np);
		assertTrue(np.matches(0, "a"));
		assertFalse(np.matches(0, "b"));

		Pred<Integer> ep = model.buildEdgePred(new CodePred("x%2==1"));
		assertNotNull(ep);
		assertTrue(ep.matches(0, 1));
		assertFalse(ep.matches(0, 2));
	}

	@Test
	void test_bareword_no_method() {
		TestModel model = new TestModel();

		RuntimeException e = assertThrows(RuntimeException.class, () -> {
			model.buildNodePred(new BarePred("no_such_method", null));
		});
		assertEquals("No method corresponds to bareword \"no_such_method\"", e.getMessage());
	}

	@Test
	void test_bareword_basic_operation() {
		TestModel model = new TestModel();
		model.initializeCodeContext();

		Pred<String> np = model.buildNodePred(new BarePred("isa", null));
		assertNotNull(np);
		assertTrue(np.matches(0, "a"));
		assertFalse(np.matches(0, "b"));
	}
}
