| Feature                         | Option 1: `ca-certificates` + OpenSSL                                                                                             | Option 2: `rustls-tls`                                                                          |
| ------------------------------- | --------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------- |
| **Depends on native libraries** | Yes: uses system-installed OpenSSL                                                                                                | No: uses pure Rust TLS implementation                                                           |
| **Root certificate management** | You must install the `ca-certificates` package and run `update-ca-certificates` to generate `/etc/ssl/certs/ca-certificates.crt`. | Nothing extra needed: `rustls` includes its own root CA bundle.                                 |
| **Image size impact**           | +\~5 MB from `ca-certificates`                                                                                                    | Slightly larger Rust binary due to `rustls`, but no extra packages.                             |
| **Dockerfile complexity**       | `dockerfile<br>RUN apt-get install -y ca-certificates && update-ca-certificates`                                                  | No changes to the Dockerfile needed for certificates.                                           |
| **Rust configuration**          | None: `reqwest` uses OpenSSL by default                                                                                           | In `Cargo.toml`:<br>`toml<br>reqwest = { default-features = false, features = ["rustls-tls"] }` |
| **Compatibility**               | Widely used in Linux/Unix environments                                                                                            | Fully cross-platform, Rust-native                                                               |
| **Potential pitfalls**          | Will fail if `ca-certificates` is missing or outdated                                                                             | May conflict with native TLS libs if you're mixing both                                         |

**Which one should you choose?**

* **Use OpenSSL + `ca-certificates`** for maximum compatibility in traditional Linux environments.
* **Use `reqwest` with `rustls-tls`** for a simpler, more self-contained container without system-level cert management.
