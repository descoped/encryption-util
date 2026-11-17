# CLAUDE.md

Guidance for Claude Code in this repository.

## What this is

`io.descoped.encryption:encryption-util`, JPMS module `io.descoped.encryption.util`: authenticated encryption with
AES-GCM and password-based key derivation with PBKDF2-HMAC-SHA256, for Java services. Owned by Descoped. One public
class does the work (`EncryptionClient`), with `Algorithm` and two exceptions. `README.md` is the user documentation
and must stay true when behaviour changes, including the ciphertext format table.

## Invariants (never violate)

- **Java 17 baseline** (`maven.compiler.release` 17): every class file is Java 17 whatever JDK builds it. CI builds
  and tests on JDK 17 only, in one job (`ci.yml`). Nothing above Java 17 in main or test code (for example,
  `ExecutorService` is not `AutoCloseable` on 17).
- **JPMS first.** Exported: `io.descoped.encryption.client` only. Users never need `opens`.
- **No runtime dependencies.** The JDK's JCA providers only. Adding a dependency (for example BouncyCastle for
  Argon2id) is the owner's decision.
- **Always the latest stable version** of every library, plugin and action. Pre-releases only on request. Old and
  outdated code and configuration is removed, not carried along.
- **Cryptography.**
  - AES-GCM with a 128-bit tag, and a fresh 96-bit nonce from `SecureRandom` on every encryption. Never a
    caller-supplied nonce, a counter, or a reused nonce.
  - Format 2: the 13-byte header (format byte and nonce) is the first associated data, so a format byte cannot be
    changed unnoticed.
  - **Format 1 stays decryptable** in both of its layouts, without associated data: 2.0.0 (AES-CBC/PKCS5 with an
    HMAC-SHA256 keyed with the AES key, checked in constant time before any decryption) and 2.0.1 (AES-GCM). Neither is
    ever written. `LegacyFormatTest` holds known answers produced by the released 2.0.0 and 2.0.1 code; never change
    those fixtures to make a test pass.
  - A new format gets a new format byte. Existing formats are never changed.
  - PBKDF2-HMAC-SHA256 at the OWASP iteration count (`PBKDF2_ITERATIONS`). Salts must be at least 16 bytes. Below
    `LEGACY_PBKDF2_ITERATIONS` is rejected.
  - A `Cipher`, `SecretKeyFactory` or `KeyGenerator` is created per call, never shared between threads. A
    `SecureRandom` may be shared.
  - Nothing is returned from a failed decryption. A key, password or plaintext never appears in an exception
    message. Nothing is logged.
  - Intermediate key and password material is cleared. The caller's arrays are never modified.
- **Publishing.** CI publishes nothing: no SNAPSHOTs (the Central Portal's monthly publishing quota is kept for
  releases) and never a release. CI holds no Central token. Releases go through the Central Portal (profiles
  `central,sign`) from the owner's machine, only with the owner's approval.

## Testing

- Unit tests (JUnit 6) are a module of their own, `io.descoped.encryption.util.test` (`src/test/java/module-info.java`),
  in package `io.descoped.encryption.client.test`. It requires the library, so surefire and IntelliJ run the tests on
  the module path and they reach only the exported API. It is `open` for JUnit only. Never put tests in the library's
  package (a split package): IntelliJ then runs them inside the library module, where `org.junit.jupiter.api` is not
  resolved. The tests write the ciphertext layout out as their own constants and do not read the library's.

## Maven Wrapper

- `./mvnw` pins Maven (`.mvn/wrapper/maven-wrapper.properties`, type `only-script`, so no jar in the repository) and
  checks the download against `distributionSha256Sum`. CI runs `./mvnw`. When Maven is bumped, by Renovate or by hand,
  set `distributionSha256Sum` to the SHA-256 of the new `apache-maven-<version>-bin.zip`, after checking that zip
  against the `.sha512` Maven publishes next to it. A stale checksum fails the build, it never skips the check.

## Commands

```sh
./mvnw verify                    # compile with -Xlint:all -Werror, tests on the module path (JUnit 6)
./mvnw verify javadoc:javadoc    # plus Javadoc with doclint, warnings fail the build
src/it/consumer/run.sh           # after package: a separate named module uses the jar, module path and class path
./mvnw verify -P coverage        # JaCoCo report in target/site/jacoco
./mvnw deploy -P central,secrets # SNAPSHOT to the Central Portal by hand (the token comes from ~/.mavenrc)
```
