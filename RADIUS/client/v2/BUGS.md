No known bugs.

Previously tracked here and fixed:

- `packet` scenarios sent well-known IPv4 attributes (NAS-IP-Address,
  Framed-IP-Address, Framed-IP-Netmask, Login-IP-Host) as literal ASCII
  text instead of their required 4 raw octets when given a dotted-quad
  `value:` (e.g. `value: 127.0.0.1` was sent as 9 bytes of text instead of
  the 4 bytes `7f000001`), which some strict RADIUS servers/parsers
  rejected as malformed. Fixed in `packet.go` (`maybeEncodeIPv4`).

- `packet` scenarios had no way to send a *valid* Message-Authenticator
  without hand-computing and pasting in a hex value — a
  `type: Message-Authenticator` entry with no value/length is now
  computed automatically (RFC 2869 HMAC-MD5 over the whole packet), same
  as `otp`/`fuzz` scenarios already did. Fixed in `packet.go`
  (`appendAttrSpec` + `runPacketScenario`). See the
  "status-with-message-authenticator" example in `config.example.yaml`.
