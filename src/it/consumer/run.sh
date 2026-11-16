#!/usr/bin/env bash
# JPMS consumer smoke test: compiles a small named module against the built library jar and runs it on the module
# path and on the class path. Run after `mvn package`.
set -euo pipefail

root=$(cd "$(dirname "$0")/../../.." && pwd)
it="$root/src/it/consumer"
out="$root/target/it-consumer"
cd "$root"

version=$(sed -n 's/^version=//p' target/maven-archiver/pom.properties)
jar="target/encryption-util-$version.jar"

rm -rf "$out"
mkdir -p "$out/classes"
javac --release 17 -Xlint:all -Werror --module-path "$jar" -d "$out/classes" $(find "$it/src" -name '*.java')

echo "== library module descriptor"
jar --describe-module --file "$jar"

echo "== jdeps: requires that are missing or unused"
jdeps --multi-release 17 --module-path "$jar" --check io.descoped.encryption.util

echo "== module path"
java --module-path "$jar:$out/classes" --module consumer/consumer.Main module

echo "== class path"
java --class-path "$jar:$out/classes" consumer.Main classpath
