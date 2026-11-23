# EastGuard Scripts Directory

Scripts are organized into platform-specific subdirectories:

- **`linux/`**: Native POSIX Bash scripts (`.sh`) for Linux and macOS environments.
  - `sources.sh`: Generates `sources.txt` javac argument list.
  - `gen-certs.sh`: Generates PKI key material, CA, and certificates using `keytool`.
  - `gen-credentials.sh`: Generates high-entropy control plane secrets and HMAC keys.
  - `reset-demo.sh`: Cleans demo journal and bootstraps revision 1.
  - `run-demo.sh`: Starts the end-to-end multi-process demo in spec §9.2 order.

- **`windows/`**: PowerShell scripts (`.ps1`) for Windows environments.
  - `sources.ps1`: Generates `sources.txt` javac argument list.
  - `gen-certs.ps1`: Generates PKI key material, CA, and certificates using `keytool`.
  - `gen-credentials.ps1`: Generates high-entropy control plane secrets and HMAC keys.
  - `reset-demo.ps1`: Cleans demo journal and bootstraps revision 1.
  - `run-demo.ps1`: Starts the end-to-end multi-process demo in spec §9.2 order.


