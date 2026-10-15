# Third-party engine notices

TunnelPannel renders paired configurations and invokes separately installed engines. It does not acquire ownership of those engines or change their licenses. No private repository source was copied into this extension.

## WaterWall-H

Source: [DashSaman/WaterWall-H](https://github.com/DashSaman/WaterWall-H/tree/613bb32c93db40b09cb915070e5f7ff09ad3c81d), pinned commit `613bb32c93db40b09cb915070e5f7ff09ad3c81d`. Its [Mozilla Public License 2.0](licenses/WaterWall-H-MPL-2.0.txt) applies to the upstream files and our modifications to them. Upstream copyright and license notices remain in the source checkout.

The complete reproducible modification source is in `engines/waterwall_h.py`: `patch_owned_ca()` augments the CA store without disabling verification; `patch_http2_drain()` preserves pending HTTP2 DATA on EOF and bounds both upload and download queues with producer backpressure. Patch set `ca1-h2drain3` modifies `tunnels/TlsClient/instance/create.c`; HttpServer `include/HttpServer/structure.h`, `downstream/fin.c`, `upstream/fin.c`, `upstream/payload.c`, `common/transport.c`; and HttpClient `include/HttpClient/structure.h`, `common/transport.c`. The installer fetches the exact upstream commit, restores those source files, applies the included modifications and builds as `tp-wwbuild`. Source and build log remain in `/var/cache/tunnelpannel-build/waterwall-h/<commit>/`; installed metadata records commit, patch set and binary SHA-256. Distributors of a generated binary must also make the corresponding upstream source and these modifications available under MPL-2.0.

## Hedioum and sing-box

Hedioum recipes use the [official pinned v0.11.3-pv1 release](https://github.com/DashSaman/Hedioum-Pool-Tunnel/releases/tag/v0.11.3-pv1); binaries are verified by fixed amd64/arm64 SHA-256 digests. Existing operator binaries are preserved. Refer to its source repository for its license and third-party notices.

VMess, AnyTLS, ShadowTLS3 + Shadowsocks AEAD 2022, and NaiveProxy recipes use [sing-box](https://github.com/SagerNet/sing-box). Its upstream license and dependencies apply to the separately installed executable. Configuration behavior was checked against the official v1.14.3 implementation; protocol names are not additional independent engines. The Naive outbound requires a build with Naive support and verifies the owned CA and server name.

Existing engine notices and licenses remain applicable to the original methods. This file documents the extension's sources; it does not grant a new license for the repository as a whole.
