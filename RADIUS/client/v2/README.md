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

### Pass/fail with `response:`

Any `otp`, `raw`, `fuzz`, or `packet` scenario may set a `response:` field —
the RADIUS response code the scenario must get back to count as a pass:
```yaml
    response: Accept       # short aliases: Accept | Reject | Challenge
    # response: Access-Accept   # or a full RADIUS code name
    # response: 2               # or a numeric code
```
Left unset, a scenario is unchanged from before: it passes as long as it ran
without a network/protocol error, regardless of which code came back. Set
`response:` and a mismatch makes the scenario FAILED in the log and the
end-of-run summary (and the process exit non-zero), even though the request
was sent and a reply was received without error — e.g. `response: Reject` on
a `raw` scenario asserts the server must reject that packet, and turns an
unexpected Accept into a reported test failure instead of just a log line.
For `fuzz`, `response:` applies to **every** case in the wordlist, not just
one — useful for asserting a server rejects an entire batch of malformed
requests.

### Config schema

```yaml
addr: "localhost:1812"        # top-level default; any scenario may override
secret: "MyRadiusSecret123"   # top-level default; any scenario may override
timeout: 5s                   # Go duration string; top-level default (5s if omitted)

scenarios:
  - name: "otp-happy-path"    # used in logs/summary
    type: otp                 # raw | fuzz | otp | packet
    # addr / secret / timeout may also be set here to override the top level
    # response: Accept        # optional pass/fail assertion, see below
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

**`type: packet`** — build a single RADIUS packet entirely from an explicit
attribute list. Nothing is added automatically beyond what you list in
`attrs`, giving full manual control over framing:
```yaml
    code: Status-Server               # optional; numeric or name, default Access-Request
    id: 5                             # optional; 0-255, default random
    authenticator: "000102030405060708090a0b0c0d0e0f"   # optional; 16 bytes hex, default random
    attrs:
      - type: User-Name                # numeric (0-255) or known name, see dictionary.go
        value: "art"                   # literal UTF-8 string, or hex:<hexstring>
        # length: 5                    # optional: override the encoded Length byte
      - type: User-Password
        value: "hex:c1ca81231bf609d1d3a7704f3ba549c3"
      - type: NAS-IP-Address
        value: 127.0.0.1               # dotted-quad text is auto-encoded as the
                                        # required 4 raw octets, not sent as ASCII text
      - type: Message-Authenticator    # value/length both omitted: computed for you
                                        # (RFC 2869 HMAC-MD5 over the whole packet)
```
This is the tool to reach for when you want to test something the normal
encoder always includes but you want to leave out — most notably, sending a
request **without a Message-Authenticator attribute at all**: just don't put
a `type: Message-Authenticator` (or `80`) entry in `attrs`. If you *do* list
one but leave both `value:` and `length:` unset, it's computed automatically
the same way `otp`/`fuzz` scenarios already do it. Giving it an explicit
`value:` (e.g. `hex:...`) or `length:` opts back out of that and is sent
exactly as written — useful for testing a deliberately wrong or malformed
Message-Authenticator. The same applies to a PAP-encrypted `User-Password`:
there's no automatic PAP encryption here, so supply it yourself via `hex:`.
Any `attrs[]` entry can also set an explicit `length:` to send a
deliberately mismatched Length byte, same idea as the `fuzz` mode's
oversized-value wraparound.

A handful of well-known attributes whose value RFC 2865 requires to be a
raw 4-octet IPv4 address — `NAS-IP-Address`, `Framed-IP-Address`,
`Framed-IP-Netmask`, `Login-IP-Host` — get the same treatment: writing
`value: 127.0.0.1` sends the 4 binary octets, not the 9-byte ASCII string.
Use `hex:` instead if you need to send something that isn't a well-formed
IPv4 address for one of these (e.g. to test how a server handles that).

For `code: Accounting-Request` or `code: Status-Server`, leaving
`authenticator:` unset does **not** generate a random one like every other
code does. Neither of those codes carries a `User-Password` to justify a
random value, so RFC 5997 §3 (Status-Server) and RFC 2866 §3
(Accounting-Request) instead define the Request Authenticator as an
integrity check — `MD5(header + attributes + secret)`, computed with the
Authenticator field itself zeroed — and that's what gets computed and
filled in automatically. Some servers reject a random authenticator here
with something like "bad authenticator or shared secret"; give an explicit
`authenticator:` hex value to opt back out and send an arbitrary one on
purpose instead.

See `client/v2/config.example.yaml` (including a ready-to-run
"no-message-authenticator" `packet` example with a real, correctly
PAP-encrypted password, and a "status-with-message-authenticator" example
covering the auto-computed Message-Authenticator, auto-computed
accounting-style Request Authenticator, and NAS-IP-Address case)
and `client/v2/fuzz.example.txt` for complete
working examples covering all four scenario types.

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
