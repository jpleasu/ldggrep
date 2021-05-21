package com.github.jpleasu.ldggrep.internal;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Collection;

import org.junit.jupiter.api.Test;

import com.github.jpleasu.ldggrep.*;
import com.github.jpleasu.ldggrep.parser.Expr;

public class TestPredicateMachine {
	@Test
	@SuppressWarnings("unchecked")
	void test_basic_operation() {
		LDGModel<String, Integer> model = new LDGModel<>();
		PredicateMachine<String, Integer> predicateMachine =
			new PredicateMachine<>(model, Expr.parse("</a/> ."));
		Collection<Trans> s0 = predicateMachine.transitionsFrom(PredicateMachine.INITIAL_STATE);
		assertEquals(1, s0.size());

		Trans t0 = s0.iterator().next();
		assertEquals(NTrans.class, t0.getClass());

		Pred<String> np = ((NTrans<String>) t0).p;
		assertTrue(np.matches(0, "a"));
		assertFalse(np.matches(0, "b"));

		Collection<Trans> s1 = predicateMachine.transitionsFrom(t0.target);
		assertEquals(1, s1.size());

		Trans t1 = s1.iterator().next();
		assertEquals(ETrans.class, t1.getClass());

		Pred<Integer> ep = ((ETrans<Integer>) t1).p;
		assertTrue(ep.matches(0, 0));
		assertTrue(ep.matches(0, 1));
		assertTrue(ep.matches(0, 42));

		assertEquals(PredicateMachine.FINAL_STATE, t1.target);
	}

}
