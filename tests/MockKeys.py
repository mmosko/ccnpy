#  Copyright 2024 Marc Mosko
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
import array

private_key_pem=b'''-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEA7QdUuaoTr4gA1bMoCdjUNPqpb7f211TYFcahHhaBPnBwQwYj
NIV1HUmKnJiLn59F36iZFYgNR53O30F7g0/oR2MWVaJoeSKq7UP7gqlSjrplZEaI
Yx1MvFKjWAHRDsVTdPNGKqNt8wFZgzxTZw24IlBIk0hOXlgV70TIbo9TvZ9Wl7nI
Uihz66OmY1b+DEokjphEjzX1PJK/a/Xat4L0CRnUVSZ+VGbaqbzkT1FKHTfCVSk6
Jcz7/EtcKnKyajCVcQKoL8Zgv4oXqWzXcGJKewM/87c2S2qMwdocG0XZx90GqEI9
Jk+Rs6JKJoYf9GTW6yDBAH+wGISSPQj0U2GyYwIDAQABAoIBABtFIKZLvwAO8amk
dxLK838055GG5MtZY5L9y0Oe6ze3z/KmHh7Iy/SWpW/mzQmMVYmp6BLmGEEJEuf0
rLUq2Fp+N++aQ9LL/kZV7/XUbT8misvCoaZllJKGH2zcqKS+Zx+pbYUyUFAI87d5
lU7h8TFhczgetYV9NOjWTQkLTGMgXTNiOLraoXqTcO7jB5IrtAtewrImiI7q5a4L
nE03hs2u19iWHPkGvdt7fSMJ66Krju15Afe25Qxwf7n02yJkFcRxa30YGfL3MkMM
wEyA8BjFPaUYd0NuuAblK3JQ7MUEU371lINQRM+Z4QZowIZZbm0uJpHqQ4NcCsNn
LIP+miECgYEA957kkw4z/xdCQcfK5B3vSBf+VhIpNhH/vE18Z7i0kTOX0BedEMpX
3TUd1nzfbyymZAxk3Vis1Dj46NvE2+GDaiCzm7PPsZeSGE7LNtCi9930Q6pQsId5
+iWQhatRsg6zfQarhI6ul8YYcB3zwL51H8eRZDl1NXwy8oI5eyvEgw0CgYEA9Qyu
Oh44wcrXswazrJBmVGoC+kXenZJ8lVp1S5UnEZRDfhSXf8RUj+sARbCGRYedZqtd
2H+vaG5AyiRJcCjSYCAfyh/DYYFKzJ76D6xV6h5NpbJx6xUWEwfxgP84Of3YK6z1
zifU2eGhu5o8CJhU3eRA348x82zvxPXSU/inby8CgYBSDs/Eg9JrWHPWhLURv3HK
PFlGgKIzjudmqW7umGEONUC77vdX1xYi8jU/HQaWOv+w7AKI75fmhDLIR/wGucbo
5olescnEGmyJraLeOWmoJl+KBOjUdzDO2p/4C/v4u7JzXkB8nyPwm+8BSIu8deEu
dN4Tjo7u+IeRoeIWlTx8CQKBgBu7oKgxLWk5RKodMw5vlTUufkHG0IfywSjCAQ5Z
xf8mUXEecXrjRFK5XOGGNdv+miC5ejh7UuW1vJ1j9++6nvyEBjUA3ULWuBlqUJCf
h2WkolMDXAMn8sSanIll2P4vLVzcCUGYnm0+LOinbu3mF4y5PWJPuW58QLKAw5n/
RSu/AoGAH5miv08oDmLaxSBG0+7pukI3WK8AskxtFvhdvLH3zkHvYBXglBGfRVNe
x03TA4KebgVHxWU+ozn/jOFwXg1m8inSt3LolR9pARSHXCbwerhvE9fN+QA9CPqq
YHoJ5UwIFj2Ifw/YHKJAgxG3vxApbLqMJEiCg3WajkqUhjhXZU8=
-----END RSA PRIVATE KEY-----'''


# openssl rsa -in test_key.pem -pubout -out rsa_pub.pem
public_key_pem=b'''-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7QdUuaoTr4gA1bMoCdjU
NPqpb7f211TYFcahHhaBPnBwQwYjNIV1HUmKnJiLn59F36iZFYgNR53O30F7g0/o
R2MWVaJoeSKq7UP7gqlSjrplZEaIYx1MvFKjWAHRDsVTdPNGKqNt8wFZgzxTZw24
IlBIk0hOXlgV70TIbo9TvZ9Wl7nIUihz66OmY1b+DEokjphEjzX1PJK/a/Xat4L0
CRnUVSZ+VGbaqbzkT1FKHTfCVSk6Jcz7/EtcKnKyajCVcQKoL8Zgv4oXqWzXcGJK
ewM/87c2S2qMwdocG0XZx90GqEI9Jk+Rs6JKJoYf9GTW6yDBAH+wGISSPQj0U2Gy
YwIDAQAB
-----END PUBLIC KEY-----'''

# openssl genrsa -out shared_key.pem
shared_512_key_pem = b'''-----BEGIN RSA PRIVATE KEY-----
MIIBOwIBAAJBAK4kjpc4dzaVXnFJt1gz1Fg+k4U4Nug2UoqrE6m44w+Gt5H+bUZO
WpPVZ8bD1b/w9q5akwoaGlsg0pM2dxtCGYECAwEAAQJARzAslkb//PFM3VT8PXNa
oARcu/4B/CWQ0p0i+aPaNpL391he3srt1WZ2KqzHQj6efY0UbjAGYeAaf2MZblly
QQIhAN+2WJfHjG0whLCFB1fnBCY6PCwseRhsgCbOALE3Bo7pAiEAx0a7g2I1ME01
8hQtK4lZNEmLNbqkYAtxNJv2iWudhtkCIQClonHHtvRO58xmkagVOjNFRnrEzgy+
u57KnF3A2Bff+QIhAJsu/f+Gjx0aQ5RNGg/5WbpaO0qQGkmhH3t0qTzCzV2hAiBK
xtyhY1cG4AUNWXPBDVpXvUxxIEMPf3pD5TKOQtTlJA==
-----END RSA PRIVATE KEY-----'''

shared_512_pub_pem = b'''-----BEGIN PUBLIC KEY-----
MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAK4kjpc4dzaVXnFJt1gz1Fg+k4U4Nug2
UoqrE6m44w+Gt5H+bUZOWpPVZ8bD1b/w9q5akwoaGlsg0pM2dxtCGYECAwEAAQ==
-----END PUBLIC KEY-----'''

shared_1024_key_pem = b'''-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQDBe6hvOW8HzZAHTf8R1ve5RWt6oKQPDhndyxyYY/HZIAm/8AV4
P5dCfla1hVHy32oCQnzVECED6yXw2M8eRZPbl7zMi74Hddso2n3VKdXOTHaLovHB
SOuP4CmMWyliPG+DjuwjIQ+MMG4Xwc9ULNP+Dr0RpAP+GYNHr3+JgIJTFQIDAQAB
AoGAL2DIbfPybEa57g/7VbL+FjAZkX2krssVKmqCJg7TOgfOW2G69ScdMvsc4HY1
CvQKUWNWjhXU/9ClCcUNcqw2+DEdgNVTnHag4KUMnDjalOlE+iT6AxFSHr/KE+s4
eGzszzvjC0mCNburgTwt0nfL/ycIguaHBFZgp/Ibm03lPEECQQD3+BxmHgiOQm/U
rhD1hE5NVXtkOmb/D7ZICQuEg7bspAFpx64pwSMU9aPMwW9V1Jhq+2ZObFKXnCaS
csqF3ORXAkEAx7/Out273rSuuAJIVB02bXzkskVjzn90PFtnOwMG2tBrSl7KhkcF
WDJQGhQKhl47u6BUkey+sQqiN8rv1R5AcwJAFn9iRDmRWSbZ8pfgXgYk/Is26L8L
vTR1u09mxh0VKZ8vqaM+P/eP8UTgGaGrMkRZl8s7Wv4k+DBop3zWtxJ1fQJBAL4i
F3fMBD4SopTIp2xZeitxzIbcggpXS58AKh0D3ox+AwKBhCmYhL/U9GY+WV5ZaGZK
UPWt8j23L34ID44/A30CQBt7zC2GxNUchGumu+5QZH2LL8hiNe6lsUTHiSyJN8LI
nwPMZkjYb/ApYBDgKszARpQnFDvPe5fYQmKA0AZWHy0=
-----END RSA PRIVATE KEY-----'''

shared_1024_pub_pem = b'''-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDBe6hvOW8HzZAHTf8R1ve5RWt6
oKQPDhndyxyYY/HZIAm/8AV4P5dCfla1hVHy32oCQnzVECED6yXw2M8eRZPbl7zM
i74Hddso2n3VKdXOTHaLovHBSOuP4CmMWyliPG+DjuwjIQ+MMG4Xwc9ULNP+Dr0R
pAP+GYNHr3+JgIJTFQIDAQAB
-----END PUBLIC KEY-----'''


# openssl rand 16 | xxd - -include
aes_key = array.array('B', [
    0x18, 0xd9, 0xab, 0x0a, 0x62, 0x8c, 0x54, 0xea,
    0x32, 0x83, 0xcd, 0x80, 0x4a, 0xb1, 0x94, 0xac])
