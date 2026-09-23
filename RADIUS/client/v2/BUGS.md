  - name: "status"
    type: packet
    code: Status-Server
    authenticator: "000102030405060708090a0b0c0d0e0f"
    attrs:
      - type: NAS-IP-Address
        value: 127.0.0.1
      - type: Message-Authenticator
    response: Reject   # this repo's .raddb/clients.conf sets
                        # require_message_authenticator = no, so a valid
                        # request missing it should still be accepted;
                        # change to Reject to assert the opposite polic

2026/09/23 11:58:12 [scenario "status"] starting (type=packet)
2026/09/23 11:58:12 [packet] sending 33 bytes: 0c600021000102030405060708090a0b0c0d0e0f040b3132372e302e302e315002
2026/09/23 11:58:17 [scenario "status"] FAILED: network: read error: read udp 10.124.177.51:61286->10.126.120.208:1812: i/o timeout

error Caused by: java.lang.IllegalArgumentException: Error reading attributes, already extracted attributes: [] 
Caused by: java.lang.IllegalArgumentException: IPv4 address should be 4 octets, actual: 9

it should be like 0C3B002C000102030405060708090A0B0C0D0E0F04067F000001501200000000000000000000000000000000 with correct message-auth attr