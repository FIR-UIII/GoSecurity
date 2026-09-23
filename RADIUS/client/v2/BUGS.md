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


