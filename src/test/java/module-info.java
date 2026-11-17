/**
 * The tests, as a module of their own that uses the library the way an application module does: it requires the
 * library and reaches only its exported API. Open, so that JUnit can reach the test classes.
 */
open module io.descoped.encryption.util.test {
    requires io.descoped.encryption.util;
    requires org.junit.jupiter.api;
    requires org.junit.jupiter.params;
}
