package com.github.jpleasu.ldggrep.internal;

import static org.junit.jupiter.api.Assertions.*;

import java.lang.reflect.Method;
import java.util.List;
import java.util.function.Function;

import org.graalvm.polyglot.Context;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.github.jpleasu.ldggrep.MethodManager;
import com.github.jpleasu.ldggrep.NPred;
import com.github.jpleasu.ldggrep.parser.*;

public class TestPredicateBuilderWithNoCode {

	public class TestClass {
		@NPred
		boolean state_is_7(int state, String node) {
			return state == 7;
		}

		@NPred
		boolean contains_x(String node) {
			return node.contains("x");
		}

		@NPred(args = { "S" })
		boolean eq(String node, String s) {
			return node.equals(s);
		}

		@NPred(args = { "I" })
		boolean haslen(String node, int l) {
			return node.length() == l;
		}

		@NPred("annotation_name")
		boolean actual_method_name(String node) {
			return true;
		}

	}

	TestClass obj;
	MethodManager mm;
	Context jsctx;
	Function<String, Object> transformer;
	Function<String, String> stringify;
	PredicateBuilder<String> predicateBuilder;

	@BeforeEach()
	public void setup() {
		obj = new TestClass();
		mm = new MethodManager(obj);
		jsctx = null;
		transformer = x -> x;
		stringify = x -> x;
		predicateBuilder =
			new PredicateBuilder<String>(mm.getMethodMap(NPred.class), stringify, transformer);
	}

	@Test
	public void test_any_pred() {
		Pred<String> p = predicateBuilder.buildPred(new AnyPred());
		assertTrue(p.matches(0, "anything"));
		assertTrue(p.matches(0, "at"));
		assertTrue(p.matches(0, "all"));
	}

	@Test
	public void test_bare_with_state() {
		Pred<String> p = predicateBuilder.buildPred(new BarePred("state_is_7", null));
		assertFalse(p.matches(0, ""));
		assertTrue(p.matches(7, ""));
		assertFalse(p.matches(9, ""));

	}

	@Test
	public void test_bare_with_no_args() {
		Pred<String> p = predicateBuilder.buildPred(new BarePred("contains_x", null));
		assertTrue(p.matches(0, "I have an x"));
		assertFalse(p.matches(0, "I have an ecks"));
	}

	@Test
	public void test_bare_with_string_arg() {
		Pred<String> p = predicateBuilder.buildPred(new BarePred("eq", List.of("test string")));
		assertTrue(p.matches(0, "test string"));
		assertFalse(p.matches(0, "not test string"));
	}

	@Test
	public void test_bare_with_int_arg() {
		Pred<String> p = predicateBuilder.buildPred(new BarePred("haslen", List.of(2)));
		assertFalse(p.matches(0, "a"));
		assertTrue(p.matches(0, "ab"));
		assertFalse(p.matches(0, "abc"));
	}

	@Test
	public void test_bare_annotation_name() throws NoSuchMethodException, SecurityException {
		Pred<String> p = predicateBuilder.buildPred(new BarePred("annotation_name", null));
		assertTrue(p.matches(0, "x"));
		assertTrue(p.matches(0, "y"));

		RuntimeException e = assertThrows(RuntimeException.class, () -> {
			predicateBuilder.buildPred(new BarePred("actual_method_name", null));
		});
		Method method = TestClass.class.getDeclaredMethod("actual_method_name", String.class);
		assertNotNull(method);
		assertTrue(method.isAnnotationPresent(NPred.class));

		assertEquals("No method corresponds to bareword \"actual_method_name\"", e.getMessage());
	}

	@Test
	public void test_code_no_js() {
		RuntimeException e = assertThrows(RuntimeException.class, () -> {
			predicateBuilder.buildPred(new CodePred("x.length()==5"));
		});
		assertEquals("must set code context before building code predicates", e.getMessage());
	}

}
