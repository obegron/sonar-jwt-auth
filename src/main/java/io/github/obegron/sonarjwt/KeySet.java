package io.github.obegron.sonarjwt;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.math.BigInteger;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** The signing keys of one source, fetched through OIDC discovery and cached. */
final class KeySet {
  private static final Logger LOG = LoggerFactory.getLogger(KeySet.class);
  private static final ObjectMapper JSON = new ObjectMapper();
  private static final Duration TTL = Duration.ofMinutes(10);
  /** A key file is local and cheap to re-read, so removals take effect quickly. */
  private static final Duration FILE_TTL = Duration.ofSeconds(10);
  private static final Duration MIN_RETRY = Duration.ofSeconds(10);
  private static final Duration MAX_STALE = Duration.ofHours(6);
  private static final long WAIT_SECONDS = 3;
  /** Overall deadline for reading one response body (tests shorten it). */
  static volatile long readDeadlineSeconds = 15;
  private static final ExecutorService READER = Executors.newCachedThreadPool(r -> { Thread t = new Thread(r, "jwt-auth-keys-read"); t.setDaemon(true); return t; });
  /** Small shared pool: a hung issuer ties up one worker for at most its timeouts, not the other sources. */
  private static final ExecutorService EXEC = Executors.newFixedThreadPool(4, r -> { Thread t = new Thread(r, "jwt-auth-keys"); t.setDaemon(true); return t; });
  private static final int MAX_BODY = 1 << 20;

  /** Fetches a URL body; swappable in tests. */
  /** @param authenticated send the source's bearer token (only ever to the discovery origin) */
  interface Fetcher { String get(String url, boolean authenticated) throws Exception; }

  static Fetcher httpFetcher(AuthConfig.Source src) {
    HttpClient.Builder b = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).followRedirects(HttpClient.Redirect.NEVER);
    if (src.caFile != null) {
      try { b.sslContext(sslContextTrusting(Path.of(src.caFile))); }
      catch (Exception e) {
        LOG.error("jwt-auth source '{}': cannot load caFile {}: {}", src.name, src.caFile, e.toString());
        // fail closed: never fall back to the JVM trust store (and never send the bearer token over a connection the operator did not intend to trust)
        return (url, authenticated) -> { throw new IllegalStateException("caFile " + src.caFile + " is unusable"); };
      }
    }
    HttpClient client = b.build();
    return (url, authenticated) -> {
      HttpRequest.Builder rb = HttpRequest.newBuilder(URI.create(url)).timeout(Duration.ofSeconds(10)).GET();
      if (authenticated && src.bearerTokenFile != null) rb.header("Authorization", "Bearer " + Files.readString(Path.of(src.bearerTokenFile)).trim());
      HttpResponse<InputStream> r = client.send(rb.build(), HttpResponse.BodyHandlers.ofInputStream());
      try (InputStream in = r.body()) {
        if (r.statusCode() != 200) throw new IllegalStateException("HTTP " + r.statusCode() + " from " + url);
        // the request timeout only covers the headers: bound the whole body read too (a slow-drip server must not hold a refresh thread)
        java.util.concurrent.CompletableFuture<byte[]> read = java.util.concurrent.CompletableFuture.supplyAsync(() -> {
          try { return in.readNBytes(MAX_BODY + 1); } catch (java.io.IOException e) { throw new java.io.UncheckedIOException(e); } // never buffer more than the cap
        }, READER);
        byte[] body;
        try { body = read.get(readDeadlineSeconds, TimeUnit.SECONDS); }
        catch (java.util.concurrent.TimeoutException e) { in.close(); read.cancel(true); throw new IllegalStateException("response from " + url + " too slow"); }
        if (body.length > MAX_BODY) throw new IllegalStateException("response from " + url + " exceeds " + MAX_BODY + " bytes");
        return new String(body, java.nio.charset.StandardCharsets.UTF_8);
      }
    };
  }

  /** An SSLContext that trusts exactly the certificates in the PEM file (the JVM default trust store is not consulted). */
  static SSLContext sslContextTrusting(Path pem) throws Exception {
    KeyStore ks = KeyStore.getInstance("PKCS12");
    ks.load(null, null);
    try (InputStream in = Files.newInputStream(pem)) {
      int i = 0;
      for (Certificate c : CertificateFactory.getInstance("X.509").generateCertificates(in)) ks.setCertificateEntry("ca" + i++, c);
      if (i == 0) throw new IllegalArgumentException("no certificates in " + pem);
    }
    TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
    tmf.init(ks);
    SSLContext ctx = SSLContext.getInstance("TLS");
    ctx.init(null, tmf.getTrustManagers(), null);
    return ctx;
  }

  private final AuthConfig.Source source;
  private final Fetcher fetcher;
  private final Clock clock;
  private volatile Map<String, PublicKey> keys = Map.of();
  private volatile Instant fetchedAt = Instant.EPOCH;
  private Instant lastAttempt = Instant.EPOCH;

  KeySet(AuthConfig.Source source, Fetcher fetcher, Clock clock) { this.source = source; this.fetcher = fetcher; this.clock = clock; }

  private Future<?> inflight;

  /** Start fetching in the background (used right after the config is loaded). */
  void warmUp() { refreshAsync(false); }

  /** The key for {@code kid}. An unknown kid triggers one rate-limited refresh that the caller waits for (max 3s); a stale cache refreshes in the background. */
  PublicKey find(String kid) {
    PublicKey k = keys.get(kid);
    boolean fresh = Duration.between(fetchedAt, clock.instant()).compareTo(source.jwksFile != null ? FILE_TTL : TTL) < 0;
    if (k == null || !fresh) refreshAsync(k == null);
    if (Duration.between(fetchedAt, clock.instant()).compareTo(MAX_STALE) > 0) return null;
    return keys.get(kid);
  }

  /**
   * Only the thread that starts a fetch may wait for it (max 3 s), plus everyone while no key has ever been loaded.
   * Other callers return immediately, so unauthenticated traffic cannot park more than one request thread per source.
   */
  private void refreshAsync(boolean wait) {
    Future<?> f; boolean leader = false;
    synchronized (this) {
      Instant now = clock.instant();
      if (inflight != null && !inflight.isDone()) f = inflight;
      else if (Duration.between(lastAttempt, now).compareTo(MIN_RETRY) < 0) return;
      else { lastAttempt = now; f = inflight = EXEC.submit(this::doRefresh); leader = true; }
    }
    if (wait && (leader || keys.isEmpty())) {
      try { f.get(WAIT_SECONDS, TimeUnit.SECONDS); }
      catch (InterruptedException e) { Thread.currentThread().interrupt(); }
      catch (Exception ignored) { /* logged by doRefresh; the caller just sees "no key" */ }
    }
  }

  private void doRefresh() {
    try {
      Map<String, PublicKey> next;
      if (source.jwksFile != null) {
        next = parseJwks(Files.readString(Path.of(source.jwksFile)));
      } else {
        String base = source.effectiveDiscoveryUrl().replaceAll("/+$", "");
        String jwksUri = source.jwksUri;
        if (jwksUri == null) {
          JsonNode cfg = JSON.readTree(fetcher.get(base + "/.well-known/openid-configuration", true));
          if (!source.issuer.equals(cfg.path("issuer").asText())) {
            throw new IllegalStateException("discovery issuer '" + Log.clean(cfg.path("issuer").asText()) + "' != configured '" + source.issuer + "'");
          }
          jwksUri = cfg.path("jwks_uri").asText("");
          if (!source.allowForeignJwksHost && !sameHost(base, jwksUri))
            throw new IllegalStateException("jwks_uri host differs from discoveryUrl host (set allowForeignJwksHost to permit): " + Log.clean(jwksUri));
        }
        if (!(jwksUri.startsWith("https://") || (jwksUri.startsWith("http://") && source.allowInsecureHttp)))
          throw new IllegalStateException("jwks_uri not allowed (https required unless allowInsecureHttp): " + Log.clean(jwksUri));
        next = parseJwks(fetcher.get(jwksUri, origin(base).equals(origin(jwksUri))));
      }
      if (next.isEmpty()) throw new IllegalStateException("the issuer returned no usable signing keys"); // never replace working keys with nothing
      keys = next;
      fetchedAt = clock.instant();
      LOG.info("jwt-auth source '{}': loaded {} signing key(s)", source.name, next.size());
    } catch (Exception e) {
      LOG.warn("jwt-auth source '{}': key refresh failed, keeping previous keys: {}", source.name, e.toString());
    }
  }

  private static String origin(String url) {
    try { URI u = URI.create(url); return u.getScheme() + "://" + u.getHost() + ":" + (u.getPort() < 0 ? ("https".equals(u.getScheme()) ? 443 : 80) : u.getPort()); }
    catch (Exception e) { return "?"; }
  }
  private static boolean sameHost(String a, String b) {
    try { return URI.create(a).getHost().equalsIgnoreCase(URI.create(b).getHost()); } catch (Exception e) { return false; }
  }

  static Map<String, PublicKey> parseJwks(String json) throws Exception {
    Map<String, PublicKey> out = new HashMap<>();
    for (JsonNode k : JSON.readTree(json).path("keys")) {
      String kid = k.path("kid").asText("");
      if (kid.isEmpty() || "enc".equals(k.path("use").asText())) continue;
      try {
        switch (k.path("kty").asText()) {
          case "RSA" -> {
            BigInteger n = big(k.path("n").asText());
            if (n.bitLength() < 2048) { LOG.warn("jwt-auth: ignoring RSA key kid={} shorter than 2048 bits", Log.clean(kid)); continue; }
            out.put(kid, KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(n, big(k.path("e").asText()))));
          }
          case "EC" -> {
            if (!"P-256".equals(k.path("crv").asText())) continue;
            AlgorithmParameters p = AlgorithmParameters.getInstance("EC");
            p.init(new ECGenParameterSpec("secp256r1"));
            out.put(kid, KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(
                new ECPoint(big(k.path("x").asText()), big(k.path("y").asText())), p.getParameterSpec(ECParameterSpec.class))));
          }
          default -> { }
        }
      } catch (Exception e) { LOG.warn("jwt-auth: skipping unusable JWK kid={}: {}", kid, e.toString()); }
    }
    return out;
  }

  private static BigInteger big(String b64) { return new BigInteger(1, Base64.getUrlDecoder().decode(b64)); }
}
