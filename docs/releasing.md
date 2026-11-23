# Releasing encryption-util

Releases go to Maven Central only, through the Central Portal, with sources, Javadoc and GPG signatures. SNAPSHOTs
never go there: CI publishes them to maven.descoped.io (see the README).

## Who releases

Only the owner, or someone acting on the owner's explicit word, from the owner's machine. CI never releases and holds
no Central token. Every release counts against the namespace's monthly publishing limit on the Central Portal, one per
published artifact; encryption-util publishes one.

## Choices for this repository

- **Tag:** `v<version>`, from `v3.0.2` on. The earlier bare tags (`3.0.0`, `3.0.1` and older) stay as they are.
- **JDK:** any JDK 17 or newer (the class files are Java 17 either way). The GitHub release names it in full, as
  `java -version` prints it, because reproducing the jars needs the same JDK.
- **Release notes:** written at release time in the GitHub release (`--generate-notes` as a start).
- **Artifacts:** one, `io.descoped.encryption:encryption-util`.

## Before

- `master` is green: CI (build, tests, Javadoc, the JPMS consumer smoke test) and SonarCloud.
- The owner's `~/.m2/settings.xml` has the server `central` with the Portal user token, loaded by the profile
  `secrets`, and lists `https://central.sonatype.com` in its `repositoryOrigins` (Maven 3.10). The GPG key is
  available to gpg-agent.
- The version follows semantic versioning: `3.0.x` fixes, `3.x.0` additive changes, a new major only for a breaking
  change. A new ciphertext format is at most a minor release, as long as every older format stays decryptable.

## Steps

1. **Prepare:** `./mvnw release:prepare`. It asks for the release version, the tag (`v<version>`) and the next
   SNAPSHOT, builds and tests, commits "prepare release", tags, commits "prepare for next development iteration", and
   pushes both commits and the tag. It also sets `project.build.outputTimestamp` for a reproducible build.
2. **Perform:** `./mvnw release:perform -P secrets`. It checks out the tag and builds it with the profiles
   `central,sign`: sources, Javadoc, signatures. central-publishing-maven-plugin uploads the bundle with
   `autoPublish=false` and waits until it is validated. The `central` profile refuses a SNAPSHOT at `validate`.

   In batch mode, both at once, after gpg-agent holds the passphrase:

   ```sh
   ./mvnw -B release:prepare release:perform -P secrets \
       -DreleaseVersion=X -Dtag=vX -DdevelopmentVersion=Y-SNAPSHOT
   ```

3. **Publish:** in the Central Portal (https://central.sonatype.com/publishing/deployments) the deployment shows
   Validated. Check its files (jar, sources, javadoc, POM, a signature for each, checksums), then press **Publish**, or
   **Drop** to release nothing. The version reaches repo1.maven.org within about half an hour. Publishing is final: a
   version on Central can never be changed or removed.
4. **GitHub release**, once the version is on repo1:
   `gh release create v<version> --verify-tag --generate-notes`, naming the JDK in the notes. Then update the
   install version in the README.

CI builds the tag (build, tests, coverage, SonarCloud) and publishes nothing for it.

## If something fails

- **prepare failed before pushing:** `./mvnw release:rollback`, then `./mvnw release:clean`.
- **A pushed tag is not rolled back.** Fix forward with the next version, or delete the tag and revert the release
  commits, but only while nothing for the version is published.
- **perform failed, or the Portal rejected the deployment:** drop the deployment in the Portal and run
  `./mvnw release:perform -P secrets` again on the same tag (`-Darguments=-DskipTests` is fine; the tag was tested).
  It reads `release.properties`, which `release:clean` deletes and another machine does not have. Without it, build
  the tag by hand: `git checkout v<version> && ./mvnw deploy -P central,sign,secrets -DskipTests`.
- **401 from the Portal:** the token was not sent. Check the `central` server and its `repositoryOrigins`, `-P secrets`,
  and that the token is still valid.
