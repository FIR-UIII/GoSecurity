  - name: "status"
    type: packet
    code: Status-Server
    attrs:
      - type: NAS-IP-Address
        value: 127.0.0.1
      - type: Message-Authenticator
    response: Reject
    
    go run .\client\v2\. -c .\client\v2\config.yaml
2026/09/23 12:30:49 [scenario "status"] starting (type=packet)
2026/09/23 12:30:50 [packet] sending 44 bytes: 0c9f002c4c69fa9305f637f40cfc85f12ff2c07604067f00000150129e5ccacf1facbdf2056c6d3d3b32b1d5

WARN  [org.tinyradius.io.server.handler.ServerPacketCodec] (epollEventLoopGroup-2-1) Could not deserialize packet: Packet Authenticator check failed - bad authenticator or shared secret

FIXED: Status-Server (and Accounting-Request) don't carry a User-Password,
so RFC 5997 §3 / RFC 2866 §3 require the Request Authenticator to be
MD5(header + attributes + secret) with the Authenticator field zeroed for
the calculation — not an arbitrary/random value, which is what this tool
was sending for every code including these two. tinyradius enforces that
(FreeRADIUS with this repo's test config happens not to). Leaving
`authenticator:` unset for `code: Status-Server` / `code: Accounting-Request`
now computes it that way automatically; see packet.go's
`needsAccountingStyleAuth` and the "status-with-message-authenticator"
example in config.example.yaml. An explicit `authenticator:` still
overrides it for deliberate malformed-authenticator testing. 