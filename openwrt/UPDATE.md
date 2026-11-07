# OpenWrt / RouteRich 25.12.6: Probe 1.0.2-r1

Separate branch: `codex/openwrt-25.12`. Target: mediatek/filogic,
aarch64_cortex-a53. Native C APK and matching LuCI APK; not for OpenWrt 24.10.

One target at a time; polls every 30 seconds by default; bounded retry backoff;
DNS cache and reusable API/DoH transports. API origin is fixed in the binary,
and the address field is removed from LuCI.

Direct mode is on by default: Cloudflare DoH pinned to 1.1.1.1 plus socket mark
0x20000 (RouteRich RR-4.6.4 ZeroBlock bypass). The package does not change
firewall, DNS, routes or ZeroBlock settings. On an upstream intercepting router,
exclude the Probe router's WAN IP. DNS results describe the public resolver,
not the ISP's DNS. TLS verification and rejection of private/FakeIP targets
remain enabled. Domain hiding applies to the LuCI field, not network analysis.

## Install from the router console

Download `install.sh` from this release, then verify its hash against SHA256SUMS
before running it with `sh`. It downloads both APKs and checks their embedded
SHA-256 values before installation. `--allow-untrusted` applies to this APK
installation only, because the SDK build key is not a firmware trust key.
Dependencies come from the router's own configured feeds. No forced dependency
or replacement library commands are used.

The script backs up an existing config under /root. A new installation keeps
the service stopped until a node API key is entered in LuCI and saved/applied.
Use a separate node key. The release contains only a placeholder.

LuCI: Services → Roskompozor Probe. Set API key, enable autostart, save/apply.
`api_connect_ip` remains optional for local server routing with verified TLS.

## SHA-256

```
6f6551fdd2a2f3c467aae3516b93b4818cef659a56bc3d2c6408578c52bcf2db  roskompozor-probe-1.0.2-r1.apk
9b2beb806458b7fc5aa3194af64a5a6cebf7463c890dad14558628ae258385c5  luci-app-roskompozor-probe-1.0.2-r1.apk
```

See README.md in the branch for direct-check commands and measurement limits.
