package com.github.jpleasu.ldggrep;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * an optimization for graphs with a large number of nodes, methods of an LDGModel annotated 
 * with StartGen provide initial node generators.
 * 
 * When an LDGGrep query starts with a node predicate, if that predicate has an associated StartGen,
 * instead of filtering the startNodes of the LDG, the StartGen method is called.
 * 
 * The first argument of a StartGen method is always an LDG, the remaining arguments are the arguments
 * of the corresponding predicate, if any.  A StartGen must return a stream of nodes.
 * 
 * e.g.
 * <pre>
 * 		&#64;NPred(description="select nodes scoring at least S", args={"S"})
 * 		boolean scoring(N node, int S) {
 * 			return node.getScore() &#62;= S;
 * 		} 
 * 
 * 		&#64;StartGen("scoring")
 * 		Stream&#60;N&#62; scoringGenerator(MyLDG g, int S) {
 * 			// suppose we've already computed a list of the best nodes in g.
 * 			if(S &#62;= g.bestThreshold) {
 * 				return g.bestNodes.stream().filter(n-&#62;n.getScore()&#62;=S);
 * 			}
 * 			return g.startNodes().filter(n->scoring(n,S));
 * 		}
 * </pre>
 * 
 * Arguments for REGEX and LITERAL special arguments are strings. e.g.
 * <pre>
 * 		&#64;StartGen(StartGen.REGEX)
 * 		Stream&#60;N&#62; regexGenerator(MyLDG g, String regex) {
 * 			// suppose our LDG type can preform its own regular expression queries
 * 			return g.submitRegexQuery(regex).stream();
 * 		}
 * </pre>
 */
@Retention(RetentionPolicy.RUNTIME)
@Target({ ElementType.METHOD })
public @interface StartGen {
	// the name of the node predicate that this generator covers
	String value();

	static String REGEX = " regex ";
	static String LITERAL = " literal ";
}
