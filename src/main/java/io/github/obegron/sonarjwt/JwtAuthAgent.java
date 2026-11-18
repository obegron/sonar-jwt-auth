package io.github.obegron.sonarjwt;

import java.lang.instrument.Instrumentation;

/** Does nothing. Starting the JVM with -javaagent:<this jar> puts the jar on the system classpath, which is what the CoreExtension needs. */
public final class JwtAuthAgent {
  private JwtAuthAgent() { }
  public static void premain(String args, Instrumentation inst) { System.out.println("sonar-jwt-auth agent loaded"); }
}
