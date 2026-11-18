package io.github.obegron.sonarjwt;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.LongAdder;
import java.util.stream.Collectors;

/** Cheap counters, summarised in one log line every few minutes so operators can alert on them without a metrics stack. */
final class Stats {
  private final LongAdder accepted = new LongAdder(), denied = new LongAdder(), provisioned = new LongAdder();
  private final ConcurrentHashMap<String, LongAdder> rejected = new ConcurrentHashMap<>();

  void accepted() { accepted.increment(); }
  void denied() { denied.increment(); }
  void provisioned() { provisioned.increment(); }
  void rejected(String category) {
    LongAdder a = rejected.get(category);
    if (a == null && rejected.size() < 50) a = rejected.computeIfAbsent(category, k -> new LongAdder()); // bounded: categories are coarse
    if (a != null) a.increment();
  }

  /** @return a one-line summary of what happened since the last call (and resets), or null if nothing did */
  String drain() {
    long ok = accepted.sumThenReset(), den = denied.sumThenReset(), prov = provisioned.sumThenReset();
    Map<String, Long> rej = rejected.entrySet().stream().filter(e -> e.getValue().sum() > 0)
        .collect(Collectors.toMap(Map.Entry::getKey, e -> e.getValue().sumThenReset()));
    long rejTotal = rej.values().stream().mapToLong(Long::longValue).sum();
    if (ok + den + prov + rejTotal == 0) return null;
    return "jwt-auth: since last report: authenticated=" + ok + " provisioned=" + prov + " denied(scope/path/user)=" + den + " rejected=" + rejTotal
        + (rej.isEmpty() ? "" : " " + rej.entrySet().stream().sorted(Map.Entry.<String, Long>comparingByValue().reversed()).limit(5)
            .map(e -> "[" + e.getKey().trim() + ": " + e.getValue() + "]").collect(Collectors.joining(" ")));
  }
}
