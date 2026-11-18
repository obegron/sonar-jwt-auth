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

  /** Logs at WARN at most once a minute per message; the next logged line says how many were suppressed. */
  static void throttledWarn(Logger log, String message) {
    if (SEEN.size() > 2000) SEEN.clear();
    long now = System.currentTimeMillis();
    long[] st = SEEN.computeIfAbsent(message, k -> new long[] {0, 0});
    synchronized (st) {
      if (now - st[0] < WINDOW_MS) { st[1]++; return; }
      long suppressed = st[1]; st[0] = now; st[1] = 0;
      log.warn(suppressed > 0 ? message + " (+" + suppressed + " similar in the last minute)" : message);
    }
  }
}
