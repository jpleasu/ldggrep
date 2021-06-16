package com.github.jpleasu.ldggrep.internal;

import static org.junit.jupiter.api.Assertions.*;

import java.util.function.Function;

import org.graalvm.polyglot.Context;
import org.junit.jupiter.api.Test;

import com.github.jpleasu.ldggrep.*;
import com.github.jpleasu.ldggrep.parser.CodePred;

public class TestPredicateBuilderWithCode {

	MethodManager mm;
	Context codeContext;
	Function<String, Object> xToCode;
	Function<String, String> xToString;
	PredicateBuilder<String> predicateBuilder;

	public void setup_basic() {
		mm = new MethodManager(new LDGModel<>());
		codeContext = Context.newBuilder("js").allowAllAccess(true).build();
		xToCode = x -> x;
		xToString = x -> x;
		predicateBuilder =
			new PredicateBuilder<String>(mm.getMethodMap(NPred.class), xToString, xToCode);
		predicateBuilder.setCodeContext(codeContext);
	}

	@Test
	public void test_code_string_length() {
		setup_basic();
		Pred<String> p = predicateBuilder.buildPred(new CodePred("x.length==5"));
		assertFalse(p.matches(0, "12"));
		assertTrue(p.matches(0, "12345"));
		assertFalse(p.matches(0, "123456"));
	}

	@Test
	public void test_code_variable_no_binding() {
		setup_basic();
		Pred<String> p = predicateBuilder.buildPred(new CodePred("x==b"));
		RuntimeException e = assertThrows(RuntimeException.class, () -> {
			assertTrue(p.matches(0, "test string"));
		});
		assertEquals("ReferenceError: b is not defined", e.getMessage());
	}

	@Test
	public void test_code_variable_binding() {
		setup_basic();
		codeContext.getBindings("js").putMember("b", "test string");
		Pred<String> p = predicateBuilder.buildPred(new CodePred("x==b"));
		assertTrue(p.matches(0, "test string"));
		assertFalse(p.matches(0, "not test string"));
	}

	public void setup_with_int_code_converter() {
		mm = new MethodManager(new LDGModel<>());
		codeContext = Context.newBuilder("js").allowAllAccess(true).build();
		xToCode = x -> Integer.parseInt(x);
		xToString = x -> x;
		predicateBuilder =
			new PredicateBuilder<String>(mm.getMethodMap(NPred.class), xToString, xToCode);
		predicateBuilder.setCodeContext(codeContext);
	}

	@Test
	public void test_int_code_converter() {
		setup_with_int_code_converter();
		Pred<String> p = predicateBuilder.buildPred(new CodePred("typeof(x)=='number'"));
		assertTrue(p.matches(0, "0"));
		assertTrue(p.matches(0, "1"));
		NumberFormatException e = assertThrows(NumberFormatException.class, () -> {
			p.matches(0, "x");
		});
		assertEquals("For input string: \"x\"", e.getMessage());

		Pred<String> p2 = predicateBuilder.buildPred(new CodePred("x%2==0"));
		assertTrue(p2.matches(0, "0"));
		assertTrue(p2.matches(0, "42"));
		assertFalse(p2.matches(0, "123"));
		assertFalse(p2.matches(0, "8675309"));
	}
}
