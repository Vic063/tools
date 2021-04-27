# INTRODUCTION

Cisco Business Dashboard uses a Java VM to run its code.
The reverse engineering process of the passwords management component shows the following working scheme:

1) Take a base64 encoded string as input
2) Decode the base64 encoded string, it gives an encrypted payload
3) Use a static key "Who1sy0urDaddy?!" that is hashed using SHA512 algorithm
4) From hash result (which is 64 bytes long), the first 16 bytes of the result is then used as the AES encryption key
5) An AES-128-CBC decryption is performed to obtain the original data


# COMPILE

The code was tested using Debian Buster.
List of prerequisites:
 - gcc
 - libtomcrypt-dev

In order to compile the code, invoke the following command:
    gcc decrypt_cbd_password.c -o decrypt_cbd_password -ltomcrypt


# USAGE

Simply run the compiled program and issue the base64 encoded string (as shown in the JSON configuration of the device inside the CBD).
