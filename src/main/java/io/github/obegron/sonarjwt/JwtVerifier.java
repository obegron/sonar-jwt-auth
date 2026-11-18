package io.github.obegron.sonarjwt;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.Signature;
import java.time.Clock;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Validates a JWT against the configured sources and maps it to a SonarQube login. No server dependencies. */
public final class JwtVerifier {
  private static final int MAX_TOKEN_CHARS = 8192;
  private static final ObjectMapper JSON = new ObjectMapper();
  private static final Pattern LOGIN = Pattern.compile("[A-Za-z0-9_.@-]{2,100}");
  private static final Pattern PLACEHOLDER = Pattern.compile("\\$\\{(\\w+)}");

  public sealed interface Result permits NotApplicable, Accepted, Rejected {}
  /** Not a JWT of any configured issuer: let SonarQube's normal authentication handle the credential. */
  public record NotApplicable() implements Result {}
  public record Provisioning(String name, List<String> groups) {}
  /** @param provisioning null unless the rule has autoProvision */
  public record Accepted(String source, String subject, String login, Pattern projectKeyPattern, List<String> allowedPathPrefixes,
                         Provisioning provisioning) implements Result {
    public Accepted(String source, String subject, String login, Pattern projectKeyPattern, List<String> allowedPathPrefixes) {
      this(source, subject, login, projectKeyPattern, allowedPathPrefixes, null);
    }
  }
  public record Rejected(String reason) implements Result {}

  private final List<AuthConfig.Source> sources;
  private final List<KeySet> keySets;
  private final Clock clock;

  /** @param previous the verifier being replaced: its cached keys are reused for unchanged sources, so a reload never loses keys */
  public JwtVerifier(AuthConfig config, Clock clock, JwtVerifier previous) { this(config, null, clock, previous); }

  JwtVerifier(AuthConfig config, KeySet.Fetcher fetcher, Clock clock) { this(config, fetcher, clock, null); }

  private JwtVerifier(AuthConfig config, KeySet.Fetcher fetcher, Clock clock, JwtVerifier previous) {
    this.sources = config.sources;
    this.clock = clock;
    List<KeySet> ks = new ArrayList<>();
    for (AuthConfig.Source s : sources) {
      KeySet reused = null;
      if (previous != null) for (int i = 0; i < previous.sources.size(); i++)
        if (previous.sources.get(i).keyIdentity().equals(s.keyIdentity())) { reused = previous.keySets.get(i); break; }
      ks.add(reused != null ? reused : new KeySet(s, fetcher != null ? fetcher : KeySet.httpFetcher(s), clock));
    }
    this.keySets = ks;
  }

  public boolean isEmpty() { return sources.isEmpty(); }

  /** Begin fetching every source's keys in the background so the first request does not wait for them. */
  public void warmUp() { for (KeySet k : keySets) k.warmUp(); }

  public Result verify(String token) {
    if (token.length() > MAX_TOKEN_CHARS) return new NotApplicable();
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
    if (!alg.equals("RS256") && !alg.equals("ES256")) return new Rejected("unsupported alg '" + Log.clean(alg) + "'");
    String kid = header.path("kid").asText("");
    if (kid.isEmpty()) return new Rejected("missing kid");

    byte[] signed = (parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII);
    byte[] sig;
    try { sig = Base64.getUrlDecoder().decode(parts[2]); } catch (IllegalArgumentException e) { return new Rejected("bad signature encoding"); }

    String lastFailure = "no key '" + Log.clean(kid) + "' for issuer " + Log.clean(iss);
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
    if (src.maxTokenLifetimeSeconds > 0) {
      if (!c.path("iat").isNumber()) return new Rejected("missing iat (required while maxTokenLifetimeSeconds is set)");
      if (c.get("exp").asLong() - c.get("iat").asLong() > src.maxTokenLifetimeSeconds) return new Rejected("token lifetime exceeds " + src.maxTokenLifetimeSeconds + "s");
    }
    String sub = c.path("sub").asText("");
    if (sub.isEmpty()) return new Rejected("missing sub");
    for (AuthConfig.Rule r : src.rules) {
      Matcher m = r.subjectPattern.matcher(sub);
      if (!m.matches()) continue;
      String ambiguity = ambiguousCapture(r.login, m, src.name);
      if (ambiguity != null) return new Rejected("subject '" + Log.clean(sub) + "': " + ambiguity);
      String login = resolve(r.login, m, src.name);
      if (!LOGIN.matcher(login).matches()) return new Rejected("rule produced an invalid login '" + Log.clean(login) + "' for sub " + Log.clean(sub));
      Provisioning prov = null;
      if (r.autoProvision) {
        String name = r.name == null ? sub : resolve(r.name, m, src.name);
        prov = new Provisioning(name.isBlank() ? sub : name, List.copyOf(r.groups));
      }
      Pattern scope = r.projectPattern;
      if (r.projectKeyPattern != null && r.projectKeyPattern.contains("${")) {
        // per-identity scope: ${ns}-style placeholders are replaced by the *quoted* captured value, so a value can never inject regex syntax
        try { scope = Pattern.compile(resolve(r.projectKeyPattern, m, src.name, true)); }
        catch (RuntimeException e) { return new Rejected("projectKeyPattern could not be resolved for sub " + Log.clean(sub)); }
      }
      return new Accepted(src.name, sub, login, scope, src.effectiveAllowedPaths(), prov);
    }
    return new Rejected("subject '" + Log.clean(sub) + "' matches no rule of source " + src.name);
  }

  /** ${name} = regex named group; ${source} = the source's name (keeps identities of different clusters apart). */
  /**
   * Guards against two different subjects yielding the same login: a captured value may not contain a literal that sits
   * between two placeholders of the template (with "${ns}-${sa}", ns "a-b"/sa "c" would collide with ns "a"/sa "b-c").
   */
  static String ambiguousCapture(String template, Matcher m, String source) {
    Set<Character> separators = innerSeparators(template);
    if (separators.isEmpty()) return null;
    Matcher p = PLACEHOLDER.matcher(template);
    while (p.find()) {
      String v = p.group(1).equals("source") ? source : safeGroup(m, p.group(1));
      if (v != null) for (char ch : v.toCharArray()) if (separators.contains(ch))
        return "value of ${" + p.group(1) + "} contains '" + ch + "', which separates placeholders in the login template (ambiguous identity); use a separator that cannot occur in the value";
    }
    return null;
  }

  /** The literal characters that sit between two placeholders of a template. */
  static Set<Character> innerSeparators(String template) {
    Set<Character> separators = new HashSet<>();
    String[] literals = PLACEHOLDER.split(template, -1);
    for (int i = 1; i < literals.length - 1; i++) for (char ch : literals[i].toCharArray()) separators.add(ch);
    return separators;
  }

  /** The names used as ${name} in a template. */
  static List<String> placeholderNames(String template) {
    List<String> out = new ArrayList<>();
    Matcher p = PLACEHOLDER.matcher(template);
    while (p.find()) out.add(p.group(1));
    return out;
  }

  private static String safeGroup(Matcher m, String name) { try { return m.group(name); } catch (IllegalArgumentException e) { return null; } }

  private static String resolve(String template, Matcher m, String source) { return resolve(template, m, source, false); }

  private static String resolve(String template, Matcher m, String source, boolean quote) {
    Matcher p = PLACEHOLDER.matcher(template);
    StringBuilder sb = new StringBuilder();
    while (p.find()) {
      String v;
      if (p.group(1).equals("source")) v = source;
      else try { v = m.group(p.group(1)); } catch (IllegalArgumentException e) { v = null; }
      String val = v == null ? "" : v;
      p.appendReplacement(sb, Matcher.quoteReplacement(quote ? Pattern.quote(val) : val));
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
