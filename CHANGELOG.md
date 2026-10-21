# Changelog

## [2.2.0](https://github.com/dstoc/baffle/compare/v2.1.0...v2.2.0) (2026-10-21)


### Features

* **cli:** standardize successful output as JSON ([#102](https://github.com/dstoc/baffle/issues/102)) ([1430cfe](https://github.com/dstoc/baffle/commit/1430cfea58259d182db66e9935b81f28d6a579e0))

## [2.1.0](https://github.com/dstoc/baffle/compare/v2.0.0...v2.1.0) (2026-10-21)


### Features

* **config:** resolve daemon paths relative to config ([#100](https://github.com/dstoc/baffle/issues/100)) ([fb83ea8](https://github.com/dstoc/baffle/commit/fb83ea81ec5223c481fc83a579888fac1675b9c7))
* **config:** support importing session files ([#98](https://github.com/dstoc/baffle/issues/98)) ([5662396](https://github.com/dstoc/baffle/commit/5662396008cf1908ae949153288ef7f3ad84723f))
* **credentials:** add per-session credential substitution ([#101](https://github.com/dstoc/baffle/issues/101)) ([c1eb8b2](https://github.com/dstoc/baffle/commit/c1eb8b23ded713980378ab1b23be155775b4b751))

## [2.0.0](https://github.com/dstoc/baffle/compare/v1.1.1...v2.0.0) (2026-10-19)


### ⚠ BREAKING CHANGES

* **release:** Protocol v2 clients and daemons are not compatible with version 1. Upgrade baffle-client and baffle-proxy together to version 2.0.0.

### Features

* **control:** require ephemeral file-backed sessions ([#97](https://github.com/dstoc/baffle/issues/97)) ([291ed81](https://github.com/dstoc/baffle/commit/291ed81a22bd86a1d40f592f08ab9cbe551f9437))
* **control:** return CA certificate with session creation ([#96](https://github.com/dstoc/baffle/issues/96)) ([0356b4c](https://github.com/dstoc/baffle/commit/0356b4cab1933a19110be96d3127cb824949733f))


### Bug Fixes

* **control:** clean stale nested session sockets ([#70](https://github.com/dstoc/baffle/issues/70)) ([27d0b36](https://github.com/dstoc/baffle/commit/27d0b360ae46bb9083c1b99d812158384bde9799))
* **control:** validate session store before binding ([#69](https://github.com/dstoc/baffle/issues/69)) ([1a31844](https://github.com/dstoc/baffle/commit/1a31844ba9b186d632da8da32178638dca3a0469))
* **paths:** support traversable directory ancestors ([#72](https://github.com/dstoc/baffle/issues/72)) ([52ad4a1](https://github.com/dstoc/baffle/commit/52ad4a11993e213d66366de7559318ffe4d38871))
* **proxy:** buffer CONNECT headers and reject extra tokens ([#74](https://github.com/dstoc/baffle/issues/74)) ([fc7e87a](https://github.com/dstoc/baffle/commit/fc7e87adc0089a37c3fec1856a65424f3cfb9e64))
* **proxy:** release zero-lease directory records ([#71](https://github.com/dstoc/baffle/issues/71)) ([a08310e](https://github.com/dstoc/baffle/commit/a08310ee9cca412ceae0f85053cccd4eeabfe25f))
* **proxy:** reuse intercepted TLS leaf certificates ([#85](https://github.com/dstoc/baffle/issues/85)) ([c77d0c7](https://github.com/dstoc/baffle/commit/c77d0c79369388547ddf6e199f68d78ad081e417))
* **release:** publish protocol v2 as a breaking release ([3dcbf35](https://github.com/dstoc/baffle/commit/3dcbf358db32c098d572682a176df809363caad1))

## [1.1.1](https://github.com/dstoc/baffle/compare/v1.1.0...v1.1.1) (2026-10-13)


### Bug Fixes

* **cli:** register shutdown signals before readiness output ([#65](https://github.com/dstoc/baffle/issues/65)) ([e14b7ee](https://github.com/dstoc/baffle/commit/e14b7ee20f50320920d2832eccd0a8e7d9d9c0a3))
* **proxy:** keep established tunnels open ([#68](https://github.com/dstoc/baffle/issues/68)) ([d713979](https://github.com/dstoc/baffle/commit/d7139796a1233356c0f95e5398dd9d5581ae2ccc))

## [1.1.0](https://github.com/dstoc/baffle/compare/v1.0.0...v1.1.0) (2026-10-10)


### Features

* add Linux ARM64 release binary ([#63](https://github.com/dstoc/baffle/issues/63)) ([adade77](https://github.com/dstoc/baffle/commit/adade77dfc655fdd3569697914a1c97b92a34708))


### Bug Fixes

* **release:** unify workspace version selection ([#60](https://github.com/dstoc/baffle/issues/60)) ([ed5f125](https://github.com/dstoc/baffle/commit/ed5f125b87c40e7e6f15171cb2ab3cc7627c9f15))

## [1.0.0](https://github.com/dstoc/baffle/compare/v0.3.0...v1.0.0) (2026-10-02)


### ⚠ BREAKING CHANGES

* **config:** add v2 session file format ([#55](https://github.com/dstoc/baffle/issues/55))

### Features

* **ca:** add configured CA initialization ([#58](https://github.com/dstoc/baffle/issues/58)) ([739e63f](https://github.com/dstoc/baffle/commit/739e63fc427f9499656fbaf80992f4d9eb7a9e52))
* **config:** add v2 session file format ([#55](https://github.com/dstoc/baffle/issues/55)) ([4822a6a](https://github.com/dstoc/baffle/commit/4822a6a27bb0002202ba3eca03c87ba153db975b))
* **policy:** add unmatched host tunnel fallback ([#57](https://github.com/dstoc/baffle/issues/57)) ([498d250](https://github.com/dstoc/baffle/commit/498d250a674f4a2cf5314fffd5d388d578b0c30e))


### Bug Fixes

* **release:** handle empty PR outputs (baffle/54) ([#50](https://github.com/dstoc/baffle/issues/50)) ([9ecf564](https://github.com/dstoc/baffle/commit/9ecf564a9c6750a51877ebdd739ff7e36b05dca2))
* **release:** recover pending merged releases (baffle/54) ([#51](https://github.com/dstoc/baffle/issues/51)) ([8384251](https://github.com/dstoc/baffle/commit/8384251e2893292463a7d1a4b8cd969c527a8b3d))
* **release:** resume partial release artifact recovery ([#53](https://github.com/dstoc/baffle/issues/53)) ([d46d17d](https://github.com/dstoc/baffle/commit/d46d17d150e5a55dbed8afcb46a8f37493669bf8))
* **release:** surface recovery failures ([#52](https://github.com/dstoc/baffle/issues/52)) ([27e8891](https://github.com/dstoc/baffle/commit/27e8891d5b460355a8f95d764268043bc00eb16a))


### Dependencies

* The following workspace dependencies were updated
  * dependencies
    * baffle-client bumped from 0.3.0 to 0.4.0

## [0.3.0](https://github.com/dstoc/baffle/compare/v0.2.0...v0.3.0) (2026-09-28)


### Features

* **release:** publish Linux and Apple Silicon archives ([#46](https://github.com/dstoc/baffle/issues/46)) ([5d60a97](https://github.com/dstoc/baffle/commit/5d60a970b046ea7c9484f4d47ab45698debb625e))


### Bug Fixes

* **release:** synchronize generated Cargo candidates ([#49](https://github.com/dstoc/baffle/issues/49)) ([6fa7c6d](https://github.com/dstoc/baffle/commit/6fa7c6db6cb37cd377d58a0e9df7dc06db675bbd))

## [0.2.0](https://github.com/dstoc/baffle/compare/v0.1.0...v0.2.0) (2026-09-27)


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
