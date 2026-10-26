package com.eabusham.routervpn.build;

import java.io.File;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/** Shared by the shipping Gradle build and executable keystore/version tests. */
public final class AndroidBuildPolicy {
    public static final int MAX_VERSION_CODE = 2_100_000_000;
    public static final String PREFIX = "ROUTERVPN_ANDROID_";

    public final String sourceSha, versionName, certificateSHA256;
    public final int versionCode;
    public final boolean production;
    public final File storeFile;
    public final String storePassword, keyAlias, keyPassword;

    private AndroidBuildPolicy(String sha, int code, boolean production, File store,
            String storePassword, String alias, String keyPassword, String certificate) {
        sourceSha = sha;
        versionCode = code;
        versionName = "0.1." + code + "-" + (sha.equals("development") ? "dev" : sha.substring(0, 12));
        this.production = production;
        storeFile = store;
        this.storePassword = storePassword;
        keyAlias = alias;
        this.keyPassword = keyPassword;
        certificateSHA256 = certificate;
    }

    public String deliveryVariant() { return production ? "release" : "debug"; }

    public Map<String, Object> publicMetadata(String variant) {
        if (!variant.equals("debug") && !variant.equals("release")) throw invalid("unknown APK variant");
        boolean signedRelease = production && variant.equals("release");
        return Map.of("schema_version", 1, "source_sha", sourceSha,
                "application_id", "com.eabusham.routervpn", "version_code", versionCode,
                "version_name", versionName, "variant", variant,
                "signing", variant.equals("debug") ? "debug-signed" : signedRelease ? "production-signed" : "unsigned",
                "certificate_sha256", signedRelease ? certificateSHA256 : "");
    }

    public static AndroidBuildPolicy resolve(File sourceRoot, Map<String, String> environment) {
        String githubSha = text(environment, "GITHUB_SHA");
        String explicitSha = text(environment, "ROUTER_VPN_SOURCE_SHA");
        if (!githubSha.isEmpty() && !explicitSha.isEmpty() && !githubSha.equalsIgnoreCase(explicitSha)) {
            throw invalid("conflicting exact source identities");
        }
        String sha = (githubSha.isEmpty() ? explicitSha : githubSha).toLowerCase(java.util.Locale.ROOT);
        if (!sha.isEmpty() && !sha.matches("[0-9a-f]{40}")) throw invalid("invalid exact source SHA");
        boolean exact = !sha.isEmpty();
        int code;
        String capturedCode = text(environment, PREFIX + "VERSION_CODE");
        String capturedSha = text(environment, PREFIX + "VERSION_SHA").toLowerCase(java.util.Locale.ROOT);
        if (capturedCode.isEmpty() != capturedSha.isEmpty()) throw invalid("incomplete captured version identity");
        if (new File(sourceRoot, ".git").exists()) {
            if (!"false".equals(git(sourceRoot, "rev-parse", "--is-shallow-repository"))) {
                throw invalid("versioning requires complete Git history; fetch-depth must be 0");
            }
            String head = git(sourceRoot, "rev-parse", "HEAD");
            if (exact && !sha.equals(head)) throw invalid("version source does not match the checked-out commit");
            if (exact && !git(sourceRoot, "diff", "--name-only", "HEAD", "--").isEmpty()) {
                throw invalid("exact-source build has modified tracked files");
            }
            long ancestors;
            try { ancestors = Long.parseLong(git(sourceRoot, "rev-list", "--count", "HEAD")); }
            catch (NumberFormatException error) { throw invalid("invalid Git ancestry count"); }
            if (ancestors < 1 || ancestors >= MAX_VERSION_CODE) throw invalid("Git ancestry count exceeds Android version bounds");
            // Every strict descendant contains all ancestors plus at least one
            // additional commit. Rerunning a SHA never increments its version.
            code = (int) ancestors + 1;
            if (!capturedCode.isEmpty() && (!capturedSha.equals(head) || parseCode(capturedCode) != code)) {
                throw invalid("captured version does not match full Git history");
            }
        } else if (exact) {
            // The caller must obtain this pair from the verified exact-source
            // snapshot manifest. Never guess from a shallow tree or the clock.
            if (capturedCode.isEmpty() || !capturedSha.equals(sha)) {
                throw invalid("source archive requires its verified same-SHA version receipt");
            }
            code = parseCode(capturedCode);
        } else {
            if (!capturedCode.isEmpty()) throw invalid("captured version requires an exact source SHA");
            code = 1;
        }

        String required = text(environment, PREFIX + "REQUIRE_PRODUCTION");
        if (!required.isEmpty() && !required.equals("true") && !required.equals("false")) {
            throw invalid("REQUIRE_PRODUCTION must be true or false");
        }
        String path = text(environment, PREFIX + "KEYSTORE");
        if (path.isEmpty() && !text(environment, PREFIX + "KEYSTORE_BASE64").isEmpty()) {
            throw invalid("encoded keystore must be staged by build-delivery.py");
        }
        String password = environment.getOrDefault(PREFIX + "STORE_PASSWORD", "");
        String alias = text(environment, PREFIX + "KEY_ALIAS");
        String keyPassword = environment.getOrDefault(PREFIX + "KEY_PASSWORD", "");
        String fingerprint = text(environment, PREFIX + "CERT_SHA256").replace(":", "").toLowerCase(java.util.Locale.ROOT);
        String[] values = {path, password, alias, keyPassword, fingerprint};
        int supplied = 0;
        for (String value : values) if (!value.isEmpty()) supplied++;
        if (supplied == 0) {
            if (required.equals("true")) throw invalid("production signing is required but not configured");
            return new AndroidBuildPolicy(exact ? sha : "development", code, false, null, "", "", "", "");
        }
        if (supplied != values.length) throw invalid("production signing configuration is incomplete");
        if (!exact) throw invalid("production signing requires an exact source SHA");
        if (!fingerprint.matches("[0-9a-f]{64}")) throw invalid("expected signing certificate SHA-256 is invalid");
        File store = new File(path);
        if (!store.isAbsolute() || !store.isFile()) throw invalid("signing keystore must be an existing absolute file");
        char[] storeSecret = password.toCharArray(), keySecret = keyPassword.toCharArray();
        try (InputStream input = Files.newInputStream(store.toPath())) {
            KeyStore keys = KeyStore.getInstance("PKCS12");
            keys.load(input, storeSecret);
            if (!keys.isKeyEntry(alias) || !(keys.getKey(alias, keySecret) instanceof PrivateKey)) {
                throw invalid("signing alias must contain the configured private key");
            }
            if (!(keys.getCertificate(alias) instanceof X509Certificate certificate)) {
                throw invalid("signing alias must have an X.509 certificate");
            }
            certificate.checkValidity();
            String subject = certificate.getSubjectX500Principal().getName().toLowerCase(java.util.Locale.ROOT);
            if (subject.contains("cn=android debug") || alias.equalsIgnoreCase("androiddebugkey")) {
                throw invalid("an Android debug key cannot be used as the production identity");
            }
            String actual = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(certificate.getEncoded()));
            if (!MessageDigest.isEqual(actual.getBytes(StandardCharsets.US_ASCII), fingerprint.getBytes(StandardCharsets.US_ASCII))) {
                throw invalid("signing certificate does not match the explicitly pinned identity");
            }
        } catch (IllegalArgumentException error) {
            throw error;
        } catch (Exception error) {
            // Do not include provider exceptions, paths, aliases or passwords in
            // Gradle/CI output. Failed key configuration never selects debug.
            throw invalid("cannot unlock the configured signing key or validate its certificate");
        } finally {
            Arrays.fill(storeSecret, '\0');
            Arrays.fill(keySecret, '\0');
        }
        return new AndroidBuildPolicy(sha, code, true, store, password, alias, keyPassword, fingerprint);
    }

    private static int parseCode(String raw) {
        if (!raw.matches("[1-9][0-9]{0,9}")) throw invalid("captured version code is invalid");
        long value;
        try { value = Long.parseLong(raw); }
        catch (NumberFormatException error) { throw invalid("captured version code is invalid"); }
        if (value < 2 || value > MAX_VERSION_CODE) throw invalid("captured version code is outside Android bounds");
        return (int) value;
    }

    private static String text(Map<String, String> environment, String key) {
        return environment.getOrDefault(key, "").trim();
    }

    private static String git(File sourceRoot, String... arguments) {
        var command = new java.util.ArrayList<String>();
        command.add("git"); command.add("-C"); command.add(sourceRoot.getAbsolutePath());
        command.addAll(java.util.List.of(arguments));
        Process process = null;
        try {
            ProcessBuilder builder = new ProcessBuilder(command).redirectErrorStream(true);
            builder.environment().keySet().removeIf(key -> key.startsWith(PREFIX));
            process = builder.start();
            if (!process.waitFor(15, TimeUnit.SECONDS) || process.exitValue() != 0) {
                throw invalid("cannot read the exact source Git history");
            }
            byte[] output = process.getInputStream().readNBytes(65_537);
            if (output.length > 65_536) throw invalid("Git version response exceeded its bound");
            return new String(output, StandardCharsets.US_ASCII).trim();
        } catch (IllegalArgumentException error) { throw error; }
        catch (Exception error) { throw invalid("cannot read the exact source Git history"); }
        finally { if (process != null && process.isAlive()) process.destroyForcibly(); }
    }

    private static IllegalArgumentException invalid(String reason) {
        return new IllegalArgumentException("Android build policy: " + reason);
    }
}
