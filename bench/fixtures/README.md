# Benchmark TLS fixtures

These files provide deterministic test certificates for the opt-in backend
benchmarks. The private keys are public test data. Do not use them in a
deployment.

The benchmark uses the same Baffle CA, origin root, and `localhost` server
certificate for both backend selections. The pinned SHA-256 fingerprints are:

| Certificate | SHA-256 fingerprint |
| --- | --- |
| Baffle CA | `88:0E:ED:ED:4A:CC:4E:9E:3A:5B:C6:31:3B:AC:F2:84:64:DF:41:D5:5E:01:71:F9:7E:21:78:8E:AB:BE:35:D6` |
| Origin root | `37:F2:22:D7:81:9C:58:33:75:B8:E6:86:50:B9:CF:09:BE:13:50:D3:38:25:31:98:81:D8:36:64:AE:9B:02:5B` |
| Origin leaf | `0E:C9:4E:6E:FB:77:C3:D1:79:16:DD:F1:C8:01:A9:7C:47:E0:7D:4C:6E:CD:C9:4F:A3:23:D6:2D:9C:17:7C:20` |

The leaf certificate has the `localhost` SAN and server-auth use. The root
certificates have CA constraints and certificate-signing use. The Hudsucker
test runtime adds the pinned origin root to WebPKI roots for this benchmark
only. The production root set remains unchanged.
