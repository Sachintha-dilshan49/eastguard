# EastGuard

Zero-trust east-west TCP access control: Ed25519-signed short-lived leases over mTLS, an NIO gateway
that relays only after authorization, UDP telemetry to a threat detector, RMI control plane, and signed
multicast quarantine notices. Full specification: [`docs/EASTGUARD.md`](docs/EASTGUARD.md).

Java 21, JDK only. No Maven, Gradle, or external libraries.

## Build and test (PowerShell)

Run from the project root (`D:\projects\eastguard`). Needs a JDK 21 or newer `javac`/`java` on PATH;
`--release 21` pins the language level and API.

```powershell
# 1. Regenerate the javac argument file after adding/removing .java files
.\scripts\sources.ps1

# 2. Compile everything (src + test) into out\
javac --release 21 -d out "@sources.txt"

# 3. Run all tests (exit code 0 = all passed, 1 = any failure or no tests ran)
java -ea -cp out eastguard.test.AllTests

# Run only test classes whose simple name contains a filter
java -ea -cp out eastguard.test.AllTests Wire
```

Notes:

- Quote `"@sources.txt"`. Unquoted, PowerShell treats `@sources` as array splatting and javac gets no files.
- If the execution policy blocks the script, run
  `powershell -ExecutionPolicy Bypass -File scripts\sources.ps1`.
- Clean build: `Remove-Item -Recurse -Force out` then repeat steps 2–3.

## Writing tests

Tests use a JDK-only runner, no JUnit.

1. Create a class in `test/eastguard/test/` with a public no-arg constructor.
2. Add public instance methods named `test*`. Each runs on a fresh instance.
3. Use the helpers in `eastguard.test.Assert` (`assertEquals`, `assertTrue`, `assertThrows`, ...).
4. Register the class in `AllTests.TEST_CLASSES`, then regenerate `sources.txt` and rebuild.

See `SmokeTest` for a minimal example. Use deterministic `Clock`s in tests, never wall time.
