package io.github.obegron.sonarjwt;

import java.util.concurrent.ConcurrentHashMap;
import org.slf4j.Logger;

/** Log helpers: attacker-controlled text is sanitised, and repeated warnings are throttled so a bad client cannot flood the log. */
final class Log {
  private Log() { }
  private static final ConcurrentHashMap<String, long[]> SEEN = new ConcurrentHashMap<>(); // key -> {lastLogged, suppressed}
  private static final long WINDOW_MS = 60_000;

  /** Printable ASCII only, max 80 chars: no newlines, no forged log lines. */
  static String clean(String s) {
    if (s == null) return "null";
    StringBuilder b = new StringBuilder(Math.min(s.length(), 80));
    for (int i = 0; i < s.length() && b.length() < 80; i++) { char c = s.charAt(i); b.append(c >= 0x20 && c < 0x7f ? c : '?'); }
    return s.length() > 80 ? b.append("...").toString() : b.toString();
  }

  /** A bounded category for a message: quoted values and digits removed, so different clients with the same problem share a key but different problems do not. */
  static String category(String reason) {
    String c = reason.replaceAll("'[^']*'", "").replaceAll("[0-9]+", "N");
    return c.length() > 60 ? c.substring(0, 60) : c;
  }

  /**
   * Logs at WARN at most once a minute per {@code key}; the next logged line says how many were suppressed.
   * The key must be coarse (a call-site tag, optionally with a value that only authenticated callers control), never raw request data,
   * so unauthenticated clients cannot flood the log by varying their input.
   */
  static void throttledWarn(Logger log, String key, String message) {
    if (SEEN.size() > 2000) SEEN.clear();
    long now = System.currentTimeMillis();
    long[] st = SEEN.computeIfAbsent(key, k -> new long[] {0, 0});
    synchronized (st) {
      if (now - st[0] < WINDOW_MS) { st[1]++; return; }
      long suppressed = st[1]; st[0] = now; st[1] = 0;
      log.warn(suppressed > 0 ? message + " (+" + suppressed + " similar in the last minute)" : message);
    }
  }
}
