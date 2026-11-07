# Roskompozor Probe: OpenWrt 25.12

Branch `codex/openwrt-25.12` builds APK packages for OpenWrt 25.12.6,
mediatek/filogic, aarch64. The existing 24.10 IPK release remains on `main`.
This is a native C daemon; it does not install Python or a database.

## Resource limits

* One target at a time, enforced even if an old config requests more.
* Default poll interval 30 seconds; minimum 15 seconds. A pause also follows
  nonempty batches. API failures back off to 300 seconds, or the configured
  interval if it is longer. Success resets the backoff.
* API and DNS reuse their own libcurl handles and TLS session caches.
* DNS caches eight positive host answers for at most 60 seconds, bounded by
  the shortest returned TTL. No persistent DNS cache or disk log.
* HTTP/HTTPS read headers only, capped at 64 KiB per response, and close
  the connection. At most five redirects, each revalidated for SSRF.
* API responses are capped at 1 MiB; DoH responses at 64 KiB.
* Target port checks and HTTP/HTTPS remain parallel within a single target.
  Worker stacks are 128 KiB; procd uses nice 10 and bounded respawns.

## Direct measurements with ZeroBlock

The default `direct_mode: true` sets socket mark `0x20000` on target TCP/TLS,
HTTP/HTTPS, API and DoH connections. ICMP uses iputils-ping `-m 131072`.
This mark matches the bypass rule observed on RouteRich RR-4.6.4. No firewall,
routing, ZeroBlock or system DNS settings are modified by the package.
Other ZeroBlock versions or other interceptors require separate verification.

DNS A/AAAA come from Cloudflare DoH over verified HTTPS, with the transport
pinned to 1.1.1.1. This avoids bootstrap through local DNS/FakeIP. Every returned
A/AAAA address is checked before selecting up to four sorted unique addresses;
private, reserved and FakeIP answers are rejected, including answers after the
first four. DoH failure is a DNS error, with no local-DNS fallback. This mode
measures availability with a public resolver, not the ISP DNS service.

If an upstream router also intercepts traffic, exclude this router's WAN IP
there. Socket marks are local kernel metadata and do not cross routers.

The API origin is compiled as `https://roskompozor.ru`. The legacy `server`
config field is ignored and removed on saving through LuCI. LuCI has no server
address field. The optional `api_connect_ip` override remains for local server
routing; Host, SNI and TLS certificate verification retain the fixed API name.
The domain is not hidden from source inspection or network analysis.

## Build

Use the official OpenWrt 25.12.6 mediatek/filogic SDK. Copy `openwrt/` to
`package/roskompozor-probe` and `luci-app-roskompozor-probe/` to `package/`.
Install the matching SDK feed recipes for libopenssl, libjson-c, libcurl,
libidn, ca-bundle, iputils-ping, luci-base and rpcd-mod-file. Then:

```sh
make defconfig
make -j4 package/roskompozor-probe/compile V=s
make -j4 package/luci-app-roskompozor-probe/compile V=s
```

Do not install libraries from a different firmware branch or force dependencies.
The APK solver should obtain dependencies from the router's configured feeds.

## Install and configure

See [UPDATE.md](UPDATE.md) for verified release artifacts and commands.
In LuCI open Services → Roskompozor Probe, enter a separate node API key,
enable autostart and save/apply. The shipped key is a placeholder, and the
service refuses to start until a real key is saved. Config and its atomic-save
backup use mode 0600. No key is embedded in the package.

For CLI use, edit `/etc/roskompozor-probe/config.json` and run:

```sh
/usr/bin/roskompozor-probe --validate-config /etc/roskompozor-probe/config.json
/etc/init.d/roskompozor-probe enable
/etc/init.d/roskompozor-probe start
logread -e roskompozor-probe
```

One direct target check without an API key:

```sh
printf '%s\n' '{"target":"example.com","type":"domain","ports":[]}' >/tmp/probe-check.json
/usr/bin/roskompozor-probe --check-direct /tmp/probe-check.json
```

`--check` retains the system-DNS diagnostic path; `--check-direct` uses marked
connections and DoH. The daemon defaults to direct mode. Advanced CLI config
may explicitly set `direct_mode: false` for system-DNS comparison.
Do not run `--once` concurrently with the service using the same API key.

## Verification

`sh openwrt/tests/run.sh` tests the native measurement contract, HTTPS API
roundtrips with fixed origin, config limits, backoff, DoH answers/cache/FakeIP
rejection and mark failure. The fixture shim is never linked into the package.
`node openwrt/tests/test_luci.cjs` checks config saving, secret masking and ACLs.
Timeouts, DNS failures and HTTP 403 are not proof of blocking.
