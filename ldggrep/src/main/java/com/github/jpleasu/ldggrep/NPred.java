package com.github.jpleasu.ldggrep;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * methods of an LDGModel annotated with NPred are available as barewords in patterns using that model.
 * 
 * They must take an N as an argument
 * 
 */
@Retention(RetentionPolicy.RUNTIME)
@Target({ ElementType.METHOD })
public @interface NPred {
	String value() default "";

	String description() default "";

	String[] args() default {};
}
