# Encryption Util

![Build Status](https://img.shields.io/github/actions/workflow/status/descoped/encryption-util/ci.yml?branch=master)
![Latest Tag](https://img.shields.io/github/v/tag/descoped/encryption-util)
[![Maven Central](https://img.shields.io/maven-metadata/v?metadataUrl=https%3A%2F%2Frepo1.maven.org%2Fmaven2%2Fio%2Fdescoped%2Fencryption%2Fencryption-util%2Fmaven-metadata.xml&label=maven%20central)](https://central.sonatype.com/artifact/io.descoped.encryption/encryption-util)
![Renovate](https://img.shields.io/badge/renovate-enabled-brightgreen.svg)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=descoped_encryption-util&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=descoped_encryption-util)
[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=descoped_encryption-util&metric=coverage)](https://sonarcloud.io/summary/new_code?id=descoped_encryption-util)

Authenticated encryption for Java with **AES-GCM** (128- or 256-bit keys, 128-bit tag), and password-based key
derivation with **PBKDF2-HMAC-SHA256**. It runs on the JDK's own cryptography: no runtime dependencies.

- Java 17 or newer; a named JPMS module, `io.descoped.encryption.util`, that also works on the class path.
- Every encryption uses a fresh random 96-bit nonce. Each ciphertext records its format and nonce.
- Optional associated data binds a ciphertext to its context, such as a record id or a tenant.
- Decryption verifies the whole ciphertext before returning anything. A wrong key, wrong associated data or a changed
  byte fails with `DecryptionException`.
- Immutable and thread-safe; nothing is logged.

```xml
<dependency>
    <groupId>io.descoped.encryption</groupId>
    <artifactId>encryption-util</artifactId>
    <version>3.0.1</version>
</dependency>
```

```java
module my.app {
    requires io.descoped.encryption.util;
}
```

## Usage

### With a random key (preferred)

```java
EncryptionClient client = new EncryptionClient(Algorithm.AES256);

SecretKey key = client.generateKey();       // keep it in a key management system or secret store
byte[] ciphertext = client.encrypt(key, plaintext);
byte[] plaintext = client.decrypt(key, ciphertext);
```

A key you already hold as raw bytes, for example from a KMS or a mounted secret file, is wrapped with
`client.importKey(bytes)`. It must be 16 bytes for `AES128` and 32 bytes for `AES256`.

### With a password

```java
EncryptionClient client = new EncryptionClient(Algorithm.AES256);

byte[] salt = client.generateSalt();                // 16 random bytes; store it with the data, it is not secret
SecretKey key = client.deriveKey(password, salt);   // PBKDF2-HMAC-SHA256, 600,000 iterations
Arrays.fill(password, '\0');                        // the library never changes your password array
```

The same password and salt always give the same key. A salt must be at least 16 bytes. Derivation is deliberately
slow, so derive a key once and reuse it rather than deriving it per message.

### Associated data

Associated data is authenticated but not encrypted, and it is not stored in the ciphertext. Decryption must be given
the same bytes. Use it to stop a ciphertext from being copied to another record unnoticed:

```java
byte[] recordId = "customer/42".getBytes(StandardCharsets.UTF_8);
byte[] ciphertext = client.encrypt(key, plaintext, recordId);
byte[] plaintext = client.decrypt(key, ciphertext, recordId);   // DecryptionException with any other record id
```

### Errors

| Exception | When |
|---|---|
| `DecryptionException` | The ciphertext is malformed, too short or in an unknown format; or it was encrypted with another key or associated data; or it was changed. Nothing is decrypted. |
| `EncryptionException` | The platform cannot encrypt (AES-GCM unavailable). |
| `IllegalArgumentException` | The key is not AES or not this client's size; the password is empty; the salt is shorter than 16 bytes; or the iteration count is below 65,536. |
| `IllegalStateException` | The platform has no AES key generator or no PBKDF2-HMAC-SHA256 (`generateKey`, `deriveKey`). Every standard JDK has both. |
| `NullPointerException` | Any argument is `null`. |

Messages never contain keys, passwords or plaintext.

## Ciphertext format

Format 2, written by 3.x:

| Offset | Length | Content |
|---|---|---|
| 0 | 1 | Format: `0x02` |
| 1 | 12 | Random nonce |
| 13 | n | Encrypted data (same length as the plaintext) |
| 13 + n | 16 | GCM authentication tag |

A ciphertext is the plaintext length plus 29 bytes. The GCM associated data is the 13-byte header followed by the
caller's associated data. Changing the format byte, for example to downgrade to format 1, therefore fails
authentication.

Format 1 has two layouts behind the same format byte. 3.x still decrypts both, only without associated data, and
never writes either:

- **2.0.1**: the format-2 layout with `0x01`, without the header in the associated data.
- **2.0.0**: `0x01`, a 16-byte IV, AES-CBC/PKCS5Padding data, and an HMAC-SHA256 (keyed with the AES key) over IV and
  data. The HMAC is checked in constant time before anything is decrypted, which is also how the two layouts are told
  apart.

**Key usage limit:** with random nonces, encrypt no more than 2<sup>32</sup> messages with one key (NIST SP 800-38D).
Rotate keys well before that.

## Migrating from 2.x

3.0.0 is a breaking release. Data encrypted by 2.0.0 (AES-CBC with HMAC) and by 2.0.1 (AES-GCM) stays readable.

| 2.x | 3.0.0 |
|---|---|
| Java 11 | Java 17 |
| Depends on `slf4j-api`; failures logged at ERROR | No dependencies, no logging |
| `encrypt(byte[] key, byte[] data)` (2.0.1), `encrypt(byte[] key, byte[] iv, byte[] data)` (2.0.0), `decrypt(byte[] key, byte[] data)` | `encrypt(SecretKey, byte[])` / `decrypt(SecretKey, byte[])`. Wrap raw bytes with `importKey(byte[])` |
| `generateSecretKey(password, salt)` | `deriveKey(password, salt)` |
| `generateNonce()` (2.0.1), `generateIV()` (2.0.0) | Removed: `encrypt` makes the nonce |
| PBKDF2 with 65,536 iterations | 600,000 (OWASP). **A key derived from the same password and salt is different.** |
| Any non-empty salt | At least 16 bytes |
| Empty plaintext rejected | Empty plaintext allowed |
| Writes format 1 (2.0.0: CBC with HMAC; 2.0.1: GCM) | Writes format 2, reads all three |

**Keys derived from a password in 2.x:** derive them with the old iteration count to read existing data:

```java
SecretKey legacyKey = client.deriveKey(password, salt, EncryptionClient.LEGACY_PBKDF2_ITERATIONS);
byte[] plaintext = client.decrypt(legacyKey, oldCiphertext);
```

To move to the stronger derivation, decrypt with the legacy key and re-encrypt with
`client.deriveKey(password, newSalt)`. Random or imported keys work unchanged.

2.x accepted salts shorter than 16 bytes; 3.0.0 does not, even with the legacy iteration count. If your salt is shorter,
derive the legacy key with the JDK (`SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")`, 65,536 iterations,
`PBEKeySpec` with your key size), pass its bytes to `client.importKey(...)` to read the old data, and re-encrypt under a
key derived from a new 16-byte salt.

## Snapshots

CI publishes SNAPSHOTs to Descoped's public SNAPSHOT repository, `https://maven.descoped.io/`, never to Maven Central:
`X.Y.Z-SNAPSHOT` from every merge to `master`, and `X.Y.Z-<branch>-SNAPSHOT` when a branch is published by hand. To use
one, add the repository and depend on `X.Y.Z-SNAPSHOT`, never on a timestamped build: the newest build of every
SNAPSHOT version is kept, older builds are deleted after 14 days, and a branch SNAPSHOT 30 days after its last build.

```xml
<repository>
    <id>descoped-snapshots-public</id>
    <url>https://maven.descoped.io/</url>
    <releases><enabled>false</enabled></releases>
    <snapshots><enabled>true</enabled></snapshots>
</repository>
```

## Building

Build with JDK 17 or newer. `./mvnw` (the Maven Wrapper) downloads the pinned Maven, 3.10.2, and checks its SHA-256;
a Maven of your own works too if it is 3.6.3 or newer (not Maven 4 yet).

Builds are reproducible from 3.0.1 on: the jars from a release tag are byte for byte the ones on Maven
Central. Build with the same major JDK as the release (`Build-Jdk-Spec` in the jar's manifest; if a hash differs, try
the same patch version) from an LF checkout (`.gitattributes` enforces it):
`git checkout <tag> && ./mvnw -P central package -DskipTests`, then compare the SHA-256 of `target/*.jar` (main, sources
and javadoc) with the `.sha256` files on repo1.maven.org. The `.asc` signatures are not reproducible; check them with
`gpg --verify` instead.

```sh
./mvnw verify                 # compile with -Xlint:all -Werror, tests (JUnit 6)
./mvnw verify javadoc:javadoc # plus Javadoc with doclint; warnings fail the build
src/it/consumer/run.sh        # after package: a separate named module uses the jar, on the module and class path
./mvnw verify -P coverage     # JaCoCo report in target/site/jacoco
```

How a release is made: [docs/releasing.md](docs/releasing.md).

Licensed under the [Apache License, Version 2.0](LICENSE).
