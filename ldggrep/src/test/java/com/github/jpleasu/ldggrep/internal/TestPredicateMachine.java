package com.github.jpleasu.ldggrep.internal;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Collection;

import org.junit.jupiter.api.Test;

import com.github.jpleasu.ldggrep.*;
import com.github.jpleasu.ldggrep.internal.PredicateMachine.StartNPred;
import com.github.jpleasu.ldggrep.parser.Expr;

public class TestPredicateMachine {
	@Test
	@SuppressWarnings("unchecked")
	void test_basic_operation() {
		PredicateMachine<String, Integer> predicateMachine =
			new PredicateMachine<>(new LDGModel<>(), Expr.parse("</a/> ."));
		Collection<Trans> s0_trans =
			predicateMachine.transitionsFrom(PredicateMachine.INITIAL_STATE);
		assertEquals(1, s0_trans.size());

		Trans t0 = s0_trans.iterator().next();
		assertEquals(NTrans.class, t0.getClass());

		StartNPred<String> initialNTrans = predicateMachine.startNPred;
		assertNotNull(initialNTrans);
		assertEquals(t0, initialNTrans.trans);
		assertEquals("Regex(a)", initialNTrans.syntax.toString());

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

	void testNullInitial(String expr) {
		PredicateMachine<String, Integer> pm =
			new PredicateMachine<>(new LDGModel<>(), Expr.parse(expr));
		assertNull(pm.startNPred);
	}

	@Test
	void test_null_initials() {
		testNullInitial("</a/>* .");
		testNullInitial("</a/>? .");
		testNullInitial("</a/>{,3} .");
		testNullInitial(". </a/>");
		testNullInitial(".? </a/>");

		testNullInitial("(</a/> | </b/>) .");
		testNullInitial("(</a/> | </b/>){3} .");
	}

	void testStart(String expr, String expectedStart) {
		PredicateMachine<String, Integer> pm =
			new PredicateMachine<>(new LDGModel<>(), Expr.parse(expr));
		Collection<Trans> s0_trans = pm.transitionsFrom(PredicateMachine.INITIAL_STATE);
		assertEquals(1, s0_trans.size());

		Trans t0 = s0_trans.iterator().next();
		assertEquals(NTrans.class, t0.getClass());

		StartNPred<String> startNTrans = pm.startNPred;
		assertNotNull(startNTrans);
		assertEquals(t0, startNTrans.trans);
		assertEquals(expectedStart, startNTrans.syntax.toString());
	}

	@Test
	void test_starts() {
		testStart("</a/>{3} .", "Regex(a)");
		testStart("</a/>{3,} .", "Regex(a)");
		testStart("<'a'> .", "Literal(a)");
		testStart("(</a/> <'b'>){3} .", "Regex(a)");
		testStart("<max(3)> .", "Bare(max,[3])");
		testStart("<rand(1,3)> .", "Bare(rand,[1, 3])");
	}
}
