# RADIUS client v2

A RADIUS test client for appsec testing. Every exchange is logged to
stdout/stderr: raw packet bytes (hex) in both directions, and a
human-readable dump of the parsed attribute list received from the server,
e.g.:

```
2026/09/23 13:05:02 [packet] response 38 bytes: 03ca002666afa67932210cc79e07e98ad608c09150129f138c890217d41ed6eb005cba3034ea
2026/09/23 13:05:02 [packet] parsed response:
code: 03 (Access-Reject)
Identifier: ca
Length: 0026
Response Authenticator: 66afa67932210cc79e07e98ad608c091
Attributes:
  type: Message-Authenticator, len: 18, value: 9f138c890217d41ed6eb005cba3034ea
```

## Legacy flags (`-mode`)

```
go run ./client/v2 -addr localhost:1812 -secret MyRadiusSecret123 -user art -pass 12345 -mode pap
```

Only `pap` (single Access-Request) is implemented on this path. The `-mode`
flag's usage text also lists `eap-md5` — a pre-existing unimplemented stub
on the `-mode` path (hitting it panics) and out of scope here. Real `raw`
and `packet` testing is done through the scenario config below instead.

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

Any `raw` or `packet` scenario may set a `response:` field — the outcome
the scenario must get to count as a pass:
```yaml
    response: Accept       # short aliases: Accept | Reject | Challenge
    # response: Access-Accept   # or a full RADIUS code name
    # response: 2               # or a numeric code
    # response: Timeout         # or: assert the server does NOT respond at all
```
Left unset, a scenario is unchanged from before: it passes as long as it ran
without a network/protocol error, regardless of which code came back. Set
`response:` and a mismatch makes the scenario FAILED in the log and the
end-of-run summary (and the process exit non-zero), even though the request
was sent and a reply was received without error — e.g. `response: Reject` on
a `raw` scenario asserts the server must reject that packet, and turns an
unexpected Accept into a reported test failure instead of just a log line.

`response: Timeout` is the special case for a request so malformed a
well-behaved server should silently drop it rather than answer at all (e.g.
a buffer-underflow probe): the scenario now PASSES on a network read
timeout instead of FAILING with a "network: read error ... i/o timeout".
Getting any actual response, or a different kind of network error (e.g.
connection refused), still FAILS the scenario — only a genuine timeout
counts as the expected outcome.

### Config schema

```yaml
addr: "localhost:1812"        # top-level default; any scenario may override
secret: "MyRadiusSecret123"   # top-level default; any scenario may override
timeout: 5s                   # Go duration string; top-level default (5s if omitted)

scenarios:
  - name: "raw-example"       # used in logs/summary
    type: raw                 # raw | packet
    # addr / secret / timeout may also be set here to override the top level
    # response: Reject        # optional pass/fail assertion, see above
    ...
```

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
one but leave both `value:` and `length:` unset, it's computed automatically.
Giving it an explicit `value:` (e.g. `hex:...`) or `length:` opts back out of
that and is sent exactly as written — useful for testing a deliberately
wrong or malformed Message-Authenticator. The same applies to a
PAP-encrypted `User-Password`: there's no automatic PAP encryption here, so
supply it yourself via `hex:`. Any `attrs[]` entry can also set an explicit
`length:` to send a deliberately mismatched Length byte — if the resulting
2+len(value) exceeds 255, the Length byte deliberately wraps rather than
erroring, since that's itself a valid thing to want to test.

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

See `client/v2/config.example.yaml` for complete working examples covering
both scenario types, including a ready-to-run "no-message-authenticator"
`packet` example with a real, correctly PAP-encrypted password, a
"status-with-message-authenticator" example covering the auto-computed
Message-Authenticator, auto-computed accounting-style Request
Authenticator, and NAS-IP-Address case, and a "truncated-authenticator"
`raw` example demonstrating `response: Timeout`.

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
