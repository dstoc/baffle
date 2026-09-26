# Changelog

## [0.2.0](https://github.com/dstoc/baffle/compare/v0.1.0...v0.2.0) (2026-09-26)


### Features

* add atomic session reload (baffle/46) ([#41](https://github.com/dstoc/baffle/issues/41)) ([ae18c42](https://github.com/dstoc/baffle/commit/ae18c42f7d8bb83b191526fb096ee600557cb43c))
* add multi-instance Hudsucker runtime (baffle/05) ([#6](https://github.com/dstoc/baffle/issues/6)) ([243d8bd](https://github.com/dstoc/baffle/commit/243d8bd59defb4511d0d98b25c6c3413fa8b5c65))
* add per-proxy Unix socket bridges (baffle/06) ([#8](https://github.com/dstoc/baffle/issues/8)) ([535759d](https://github.com/dstoc/baffle/commit/535759d32e090dc35ed216d0939eb9ede41a4559))
* add typed Rust client library (baffle/15) ([#11](https://github.com/dstoc/baffle/issues/11)) ([1c6a754](https://github.com/dstoc/baffle/commit/1c6a754da10302b6345a11275bd9b420a8e163b6))
* **cli:** add top-level daemon control commands ([#38](https://github.com/dstoc/baffle/issues/38)) ([2d8763f](https://github.com/dstoc/baffle/commit/2d8763ff204feba19e59317f06c49a4b7d116ba0))
* enforce canonical URL path filtering ([#15](https://github.com/dstoc/baffle/issues/15)) ([cb30085](https://github.com/dstoc/baffle/commit/cb30085301611cd1cda3d98e3a0e64680c928d4e))
* enforce fail-closed selective HTTPS interception ([#14](https://github.com/dstoc/baffle/issues/14)) ([7767098](https://github.com/dstoc/baffle/commit/7767098eef00b9c81e4a093eb930ecf189175bab))
* enforce HTTPS-only proxy admission ([#21](https://github.com/dstoc/baffle/issues/21)) ([bc80323](https://github.com/dstoc/baffle/commit/bc80323aaee72f50ef4a8b916dc7130d47078483))
* enforce per-session destination policy (baffle/08) ([#9](https://github.com/dstoc/baffle/issues/9)) ([d84f313](https://github.com/dstoc/baffle/commit/d84f313d1f34343d178ee4e5dcb5b81fd41d3cf8))
* harden proxy runtime resilience (baffle/14) ([#12](https://github.com/dstoc/baffle/issues/12)) ([d490584](https://github.com/dstoc/baffle/commit/d490584abb75fd2178b4a0af817def0e5eef684b))
* implement session lifecycle leases (baffle/07) ([#10](https://github.com/dstoc/baffle/issues/10)) ([36fbc06](https://github.com/dstoc/baffle/commit/36fbc06f28d9f41e16b54fe8e9b9b494743d7c9e))
* implement Unix control protocol ([#4](https://github.com/dstoc/baffle/issues/4)) ([cee1ae4](https://github.com/dstoc/baffle/commit/cee1ae436446a2ee7048fca1d122dec47aed4817))
* initialize Baffle Rust project ([8aaf0e4](https://github.com/dstoc/baffle/commit/8aaf0e445c2e745c0118566c2fddff65b07368ca))
* inject credentials into authorized HTTPS requests ([#16](https://github.com/dstoc/baffle/issues/16)) ([efa2986](https://github.com/dstoc/baffle/commit/efa29869a5c77baea5b40b39336fe0cdcf6784cf))
* make Rama the sole proxy runtime ([#30](https://github.com/dstoc/baffle/issues/30)) ([8f970fb](https://github.com/dstoc/baffle/commit/8f970fb98b9afb533879aa3d6d3a324ab5d86c7d))
* manage shared TLS certificate authority (baffle/04) ([#3](https://github.com/dstoc/baffle/issues/3)) ([0e20930](https://github.com/dstoc/baffle/commit/0e209301a6d0ed4c713ccb612424c089abbf67a9))
* **proxy:** add experimental Rama backend ([#23](https://github.com/dstoc/baffle/issues/23)) ([ed39460](https://github.com/dstoc/baffle/commit/ed3946099491931542fc1c71416596bcb3636c9a))
* **release:** automate versioning and Linux packaging (baffle/39) ([#33](https://github.com/dstoc/baffle/issues/33)) ([b9ff373](https://github.com/dstoc/baffle/commit/b9ff3735c1c07c5b229ecc2474473c7ba7ab5a5b))
* **release:** prepare crates.io packages (baffle/44) ([#39](https://github.com/dstoc/baffle/issues/39)) ([b8997e8](https://github.com/dstoc/baffle/commit/b8997e8af957889340ec16abfb44e4baf4baacd6))
* **release:** publish crates after Release Please (baffle/45) ([#40](https://github.com/dstoc/baffle/issues/40)) ([9bdf5b7](https://github.com/dstoc/baffle/commit/9bdf5b733a62242c664cf4cb763ccd16f47e47fe))
* **secrets:** add daemon-owned secret authorization ([#5](https://github.com/dstoc/baffle/issues/5)) ([a03cf4a](https://github.com/dstoc/baffle/commit/a03cf4afd0afbe0cc049ffa79891e77f91d0ba2d))
* **security:** defer destination IP filtering to deployment egress controls ([#20](https://github.com/dstoc/baffle/issues/20)) ([dd45974](https://github.com/dstoc/baffle/commit/dd45974a81cfd8f356095f0a51879d0f70e2e490))
* support file-backed session provisioning ([#34](https://github.com/dstoc/baffle/issues/34)) ([45eb5e0](https://github.com/dstoc/baffle/commit/45eb5e09090e24a2f546951e66b5800aa6a60c19))
* validate daemon and session configuration ([bcd7b7f](https://github.com/dstoc/baffle/commit/bcd7b7f6a780f5bca07694130a232569a6a99729))


### Bug Fixes

* **release:** flatten Rama dependency table ([#35](https://github.com/dstoc/baffle/issues/35)) ([5d8ab19](https://github.com/dstoc/baffle/commit/5d8ab199f5517a92a39d88a8bf6b3fd1e3efd8e8))


### Performance Improvements

* benchmark Hudsucker and Rama runtime ([#27](https://github.com/dstoc/baffle/issues/27)) ([9439c0f](https://github.com/dstoc/baffle/commit/9439c0f5830144808c86ecf8b9d58a914ee50ece))
* **rama:** enable TCP_NODELAY on accepted client sockets ([#29](https://github.com/dstoc/baffle/issues/29)) ([cf5b0e6](https://github.com/dstoc/baffle/commit/cf5b0e64cee310b9e76fadfc0b78b7128e6cdf2c))


### Dependencies

* The following workspace dependencies were updated
  * dependencies
    * baffle-client bumped from 0.1.0 to 0.2.0
