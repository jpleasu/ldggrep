package com.github.jpleasu.ldggrep.internal;

import static org.junit.jupiter.api.Assertions.*;

import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;

import com.github.jpleasu.ldggrep.*;

public class TestMethodManager {

	public static class TestClass1 {
		@NPred(description = "node pred description")
		public boolean node_pred(Object o) {
			return false;
		}

		@EPred(description = "edge pred description")
		public boolean edge_pred(Object o) {
			return false;
		}
	}

	@Test
	public void test_basic_operation() throws NoSuchMethodException, SecurityException {
		TestClass1 obj = new TestClass1();
		MethodManager mm = new MethodManager(obj);

		AtomicInteger ai = new AtomicInteger();

		ai.set(0);
		mm.forEachPred(NPred.class, (proto, desc) -> {
			assertEquals("node_pred", proto);
			assertEquals("node pred description", desc);
			ai.incrementAndGet();
		});
		assertEquals(1, ai.get());

		ai.set(0);
		mm.forEachPred(EPred.class, (proto, desc) -> {
			assertEquals("edge_pred", proto);
			assertEquals("edge pred description", desc);
			ai.incrementAndGet();
		});
		assertEquals(1, ai.get());

		BoundMethod boundMethod = mm.getMethodMap(NPred.class).get("node_pred");
		assertNotNull(boundMethod);
		assertEquals(obj, boundMethod.obj);
		assertEquals(obj.getClass().getMethod("node_pred", Object.class), boundMethod.method);

		boundMethod = mm.getMethodMap(EPred.class).get("edge_pred");
		assertNotNull(boundMethod);
		assertEquals(obj, boundMethod.obj);
		assertEquals(obj.getClass().getMethod("edge_pred", Object.class), boundMethod.method);

		boundMethod = mm.getMethodMap(EPred.class).get("not_a_pred");
		assertNull(boundMethod);
	}

	public static class TestClass2 {
		@NPred(value = "x", description = "node pred description")
		boolean node_predx(Object o) {
			return false;
		}

		@EPred("y")
		boolean edge_pred2(Object o) {
			return false;
		}

	}

	@Test
	public void test_annotation_parsing() {
		MethodManager mm = new MethodManager(new TestClass2());

		AtomicInteger ai = new AtomicInteger();

		ai.set(0);
		mm.forEachPred(NPred.class, (proto, desc) -> {
			assertEquals("x", proto);
			assertEquals("node pred description", desc);
			ai.incrementAndGet();
		});
		assertEquals(1, ai.get());

		ai.set(0);
		mm.forEachPred(EPred.class, (proto, desc) -> {
			assertEquals("y", proto);
			assertEquals("", desc);
			ai.incrementAndGet();
		});
		assertEquals(1, ai.get());
	}
}
