# Run
```
cd .\RADIUS\
$env:radius_server="значение"
$env:secret="значение"
$env:user="значение"
$env:pass="значение"

go run .\client\v2\. -addr ${radius_server} -mode pap -secret ${secret} -user ${user} -pass ${pass}
go run .\client\v2\. -addr $env:radius_server -mode pap -secret $env:secret -user $env:user -pass $env:pass

2026/09/22 15:03:07 raw packet to server 01050042735ac97f3471ca30c855126ceb3157a3010a2d74657374666f6f021299628c8431304f9b0725f43ebfe849615012243c372649de64e27c06512b7a451ce4, authenticator 735ac97f3471ca30c855126ceb3157a3
2026/09/22 15:03:07 raw packet from server 03050026a7c0b926b87a5e73fdc05143bed69f2f501276d5ba2ff3ae746cb70e6c340dd4c7ea
2026/09/22 15:03:07 parsed attributes from server: [{80 [118 213 186 47 243 174 116 108 183 14 108 52 13 212 199 234]}]
Result: Access-Reject (Invalid credentials)
```