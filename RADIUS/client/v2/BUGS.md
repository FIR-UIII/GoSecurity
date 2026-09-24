не смог распарсить атрибут Promt

2026/09/24 13:09:41 [packet] response 148 bytes: 0b8200944d0de0243efb82cb790f59a860495dea183266623830386531302d343631352d343963322d396365372d6639376337376239646337373a524d6b747256716e695f491236d092d0b2d0b5d0b4d0b8d182d0b520d0bed0b4d0bdd0bed180d0b0d0b7d0bed0b2d18bd0b920d0bfd0b0d180d0bed0bbd18c3a204c060000000150124237c75795be1f69f7f18bec70c06e62

   |###[ Radius Attribute ]###
   |  type      = Prompt
   |  len       = 6
   |  value     = b'\x00\x00\x00\x01'

В ответе получили 
Attributes:
  type: State, len: 50, value: 66623830386531302d343631352d343963322d396365372d6639376337376239646337373a524d6b747256716e695f49 ("fb808e10-4615-49c2-9ce7-f97c77b9dc77:RMktrVqni_I")
  type: Reply-Message, len: 54, value: d092d0b2d0b5d0b4d0b8d182d0b520d0bed0b4d0bdd0bed180d0b0d0b7d0bed0b2d18bd0b920d0bfd0b0d180d0bed0bbd18c3a20
  type: Unknown, len: 6, value: 00000001
  type: Message-Authenticator, len: 18, value: 4237c75795be1f69f7f18bec70c06e62

===
2) исправить 
      - type: User-Password
        value: "hex:c1ca81231bf609d1d3a7704f3ba549c3"

Сделать 
      - type: User-Password
        value: "123" # чтобы он сам вычислял нужное значение для пароля по RFC
  или если указать hex то
      - type: User-Password
        value: "hex:c1ca81231bf609d1d3a7704f3ba549c3"