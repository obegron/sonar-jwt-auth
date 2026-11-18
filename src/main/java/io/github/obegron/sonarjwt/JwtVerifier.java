package io.github.obegron.sonarjwt;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.Signature;
import java.time.Clock;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Validates a JWT against the configured sources and maps it to a SonarQube login. No server dependencies. */
public final class JwtVerifier {
  private static final ObjectMapper JSON = new ObjectMapper();
  private static final Pattern PLACEHOLDER = Pattern.compile("\\$\\{(\\w+)}");

  public sealed interface Result permits NotApplicable, Accepted, Rejected {}
  /** Not a JWT of any configured issuer: let SonarQube's normal authentication handle the credential. */
  public record NotApplicable() implements Result {}
  public record Accepted(String source, String subject, String login, Pattern projectKeyPattern, List<String> allowedPathPrefixes) implements Result {}
  public record Rejected(String reason) implements Result {}

  private final List<AuthConfig.Source> sources;
  private final List<KeySet> keySets;
  private final Clock clock;

  public JwtVerifier(AuthConfig config, Clock clock) { this(config, KeySet.httpFetcher(), clock); }

  JwtVerifier(AuthConfig config, KeySet.Fetcher fetcher, Clock clock) {
    this.sources = config.sources;
    this.clock = clock;
    List<KeySet> ks = new ArrayList<>();
    for (AuthConfig.Source s : sources) ks.add(new KeySet(s, fetcher, clock));
    this.keySets = ks;
  }

  public boolean isEmpty() { return sources.isEmpty(); }

  public Result verify(String token) {
    String[] parts = token.split("\\.", -1);
    if (parts.length != 3) return new NotApplicable();
    JsonNode header, claims;
    try {
      header = JSON.readTree(Base64.getUrlDecoder().decode(parts[0]));
      claims = JSON.readTree(Base64.getUrlDecoder().decode(parts[1]));
    } catch (Exception e) { return new NotApplicable(); }
    if (!header.isObject() || !claims.isObject() || !claims.path("iss").isTextual()) return new NotApplicable();

    String iss = claims.get("iss").asText();
    List<Integer> candidates = new ArrayList<>();
    for (int i = 0; i < sources.size(); i++) if (sources.get(i).issuer.equals(iss)) candidates.add(i);
    if (candidates.isEmpty()) return new NotApplicable();

    // From here on the token claims to come from a trusted issuer: any failure is a rejection.
    String alg = header.path("alg").asText("");
    if (!alg.equals("RS256") && !alg.equals("ES256")) return new Rejected("unsupported alg '" + alg + "'");
    String kid = header.path("kid").asText("");
    if (kid.isEmpty()) return new Rejected("missing kid");

    byte[] signed = (parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII);
    byte[] sig;
    try { sig = Base64.getUrlDecoder().decode(parts[2]); } catch (IllegalArgumentException e) { return new Rejected("bad signature encoding"); }

    String lastFailure = "no key '" + kid + "' for issuer " + iss;
    for (int idx : candidates) {
      AuthConfig.Source src = sources.get(idx);
      PublicKey key = keySets.get(idx).find(kid);
      if (key == null) continue;
      if (!signatureValid(alg, key, signed, sig)) { lastFailure = "signature mismatch (source " + src.name + ")"; continue; }
      return checkClaims(src, claims);
    }
    return new Rejected(lastFailure);
  }

  private Result checkClaims(AuthConfig.Source src, JsonNode c) {
    long now = clock.instant().getEpochSecond(), skew = src.clockSkewSeconds;
    if (!c.path("exp").isNumber()) return new Rejected("missing exp");
    if (now - skew >= c.get("exp").asLong()) return new Rejected("token expired");
    if (c.path("nbf").isNumber() && now + skew < c.get("nbf").asLong()) return new Rejected("token not yet valid");
    if (!audienceMatches(c.path("aud"), src.audiences)) return new Rejected("audience not accepted by source " + src.name);
    String sub = c.path("sub").asText("");
    if (sub.isEmpty()) return new Rejected("missing sub");
    for (AuthConfig.Rule r : src.rules) {
      Matcher m = r.subjectPattern.matcher(sub);
      if (!m.matches()) continue;
      String login = resolve(r.login, m);
      if (login.isBlank()) return new Rejected("rule produced an empty login for sub " + sub);
      return new Accepted(src.name, sub, login, r.projectPattern, src.effectiveAllowedPaths());
    }
    return new Rejected("subject '" + sub + "' matches no rule of source " + src.name);
  }

  private static String resolve(String template, Matcher m) {
    Matcher p = PLACEHOLDER.matcher(template);
    StringBuilder sb = new StringBuilder();
    while (p.find()) {
      String v;
      try { v = m.group(p.group(1)); } catch (IllegalArgumentException e) { v = null; }
      p.appendReplacement(sb, Matcher.quoteReplacement(v == null ? "" : v));
    }
    p.appendTail(sb);
    return sb.toString();
  }

  private static boolean audienceMatches(JsonNode aud, List<String> accepted) {
    if (aud.isTextual()) return accepted.contains(aud.asText());
    if (aud.isArray()) for (JsonNode a : aud) if (a.isTextual() && accepted.contains(a.asText())) return true;
    return false;
  }

  private static boolean signatureValid(String alg, PublicKey key, byte[] data, byte[] sig) {
    try {
      boolean rsa = alg.equals("RS256");
      if (rsa != key.getAlgorithm().equals("RSA")) return false; // key type must match alg (no confusion)
      Signature s = Signature.getInstance(rsa ? "SHA256withRSA" : "SHA256withECDSA");
      s.initVerify(key);
      s.update(data);
      return s.verify(rsa ? sig : joseToDer(sig));
    } catch (Exception e) { return false; }
  }

  /** JWS ES256 signatures are raw R||S; the JDK expects DER. */
  static byte[] joseToDer(byte[] jose) {
    if (jose.length != 64) throw new IllegalArgumentException("bad ES256 signature length");
    byte[] r = trim(jose, 0), s = trim(jose, 32);
    int len = 2 + r.length + 2 + s.length;
    byte[] out = new byte[2 + len];
    out[0] = 0x30; out[1] = (byte) len;
    out[2] = 0x02; out[3] = (byte) r.length; System.arraycopy(r, 0, out, 4, r.length);
    int o = 4 + r.length;
    out[o] = 0x02; out[o + 1] = (byte) s.length; System.arraycopy(s, 0, out, o + 2, s.length);
    return out;
  }

  private static byte[] trim(byte[] b, int off) {
    int start = off;
    while (start < off + 31 && b[start] == 0) start++;
    boolean pad = (b[start] & 0x80) != 0;
    byte[] out = new byte[off + 32 - start + (pad ? 1 : 0)];
    System.arraycopy(b, start, out, pad ? 1 : 0, off + 32 - start);
    return out;
  }
}
