# RADIUS client v2

A RADIUS test client for appsec testing. Every exchange is logged to
stdout/stderr: raw packet bytes (hex) in both directions, and the parsed
attribute list received from the server, e.g.:

```
2026/09/22 15:03:07 raw packet to server 01050042735ac97f3471ca30c855126ceb3157a3010a2d74657374666f6f...
2026/09/22 15:03:07 raw packet from server 03050026a7c0b926b87a5e73fdc05143bed69f2f501276d5ba2ff3ae746cb70e6c340dd4c7ea
2026/09/22 15:03:07 parsed attributes from server: [{80 [...]}]
Result: Access-Reject (Invalid credentials)
```

## Legacy flags (`-mode`)

```
go run ./client/v2 -addr localhost:1812 -secret MyRadiusSecret123 -user art -pass 12345 -mode pap
go run ./client/v2 -addr localhost:1812 -secret MyRadiusSecret123 -user art -pass 12345 -mode pap+otp
```

Only `pap` (single Access-Request) and `pap+otp` (two-round PAP, OTP
hardcoded to `999999` on round 2) are implemented on this path. The `-mode`
flag's usage text also lists `eap-md5` and `raw`/`fuzz` — those are
pre-existing unimplemented stubs on the `-mode` path (hitting them panics)
and are out of scope here. Real `raw` and `fuzz` testing is done through the
scenario config below instead.

## Scenario config (`-c` / `-config`)

```
go run ./client/v2 -addr localhost:1812 -c client/v2/config.example.yaml
```

When `-c`/`-config` is given, it replaces `-mode` entirely: the client loads
a YAML file describing an ordered list of **scenarios** and runs each one in
turn. A scenario failing (network error, unexpected response code, failed
integrity check) is logged and does **not** abort the run — for a
security-probing tool, that's often the expected/interesting result. A
summary line is printed at the end, and the process exits non-zero if any
scenario failed.

An explicit `-addr` flag on the command line overrides the config file's
top-level `addr` for every scenario; if `-addr` is left at its default, the
config's `addr` (or a scenario's own `addr` override) is used instead.

### Config schema

```yaml
addr: "localhost:1812"        # top-level default; any scenario may override
secret: "MyRadiusSecret123"   # top-level default; any scenario may override
timeout: 5s                   # Go duration string; top-level default (5s if omitted)

scenarios:
  - name: "otp-happy-path"    # used in logs/summary
    type: otp                 # raw | fuzz | otp
    # addr / secret / timeout may also be set here to override the top level
    ...
```

**`type: otp`** — the two-round PAP+OTP chain. Round 1 sends `username`/
`password`; if the server answers Access-Challenge, round 2 sends the OTP
value as the password, echoing back the State attribute from round 1.
```yaml
    username: "art"
    password: "12345"
    otp: "999999"              # literal OTP value...
    # otp_env: "RADIUS_TEST_OTP"   # ...or read it from this env var instead
```
Exactly one of `otp` / `otp_env` must be set.

**`type: raw`** — send a complete, hand-specified raw UDP datagram, entirely
outside the normal packet encoder, for malformed/malicious packet testing
(bad lengths, bad codes, garbage attributes, etc.):
```yaml
    packet_hex: "01050014000102030405060708090a0b0c0d0e0f"
```
`packet_hex` is the full packet (header + attributes) as hex; whitespace and
newlines are stripped, so a YAML block scalar works for long packets. The
response is logged and best-effort parsed — a parse failure is logged, not
treated as a scenario failure, since a malformed response is itself a valid
outcome to observe.

**`type: fuzz`** — send one request per line of an appsec-curated wordlist
file, then optionally flood extra copies of each fuzzed datagram:
```yaml
    username: "art"                  # seed credentials for the base request
    password: "12345"
    fuzz_file: "client/v2/fuzz.example.txt"
    post_response_datagrams: 2       # default 0: extra fire-and-forget resends of the same fuzzed datagram after each case's response
```

#### `fuzz_file` wordlist format

One case per line: `attr:value`. Blank lines and `#` comments are skipped.

- `attr` — a numeric RADIUS attribute type (0-255) or a known name
  (case-insensitive, see `dictionary.go`), e.g. `User-Password` or `2`.
- `value` — a literal UTF-8 string, or `hex:<hexstring>` for raw/binary/
  invalid bytes.

```
User-Password:hex:00
User-Name:
State:hex:00112233
EAP-Message:hello
250:hex:deadbeef
```

For each line, a seed PAP request is built from the scenario's `username`/
`password`. If `attr` matches an attribute already in the seed (User-Name=1,
User-Password=2), its value is **replaced** — letting you inject raw or
malformed bytes directly into those fields, bypassing normal PAP encryption
for the password. Otherwise the attribute is **appended** alongside the
valid seed credentials (useful for fuzzing State, EAP-Message, vendor, or
unknown attribute types while credentials stay valid).

If an attribute's value makes the encoded Length byte exceed 255, the
Length byte is deliberately allowed to wrap (`byte(2+len(value))`) rather
than erroring or truncating the value — that's itself a valid fuzz case
(Length lying about actual payload size). A warning is logged whenever this
happens so it's visible in the run output, but the packet is still sent.

See `client/v2/config.example.yaml` and `client/v2/fuzz.example.txt` for a
complete working example covering all three scenario types.

## Test server

```bash
docker run -it --rm \
  --name freeradius \
  --platform linux/amd64 \
  -p 1812:1812/udp \
  -p 1813:1813/udp \
  -v "$(pwd)/client/v2/.raddb/clients.conf:/etc/freeradius/clients.conf:ro" \
  -v "$(pwd)/client/v2/.raddb/authorize:/etc/freeradius/mods-config/files/authorize:ro" \
  freeradius/freeradius-server:latest -X
```

This starts a local freeradius instance with secret `MyRadiusSecret123` and
user `art`/`12345`, matching the examples above.
