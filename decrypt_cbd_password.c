//=====================================================
// Cisco Business Dashboard software
//
// Component: Password management
// Purpose: Decode and decrypt base64 passwords of
//          user accounts and SSIDs encryption keys
//
// Initial author: Vico
// Started: 22nd Apr 2021
// File: decrypt_cbd_password.c
//=====================================================

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tomcrypt.h>

#define AES_KEY_LEN 16

/* Who1sy0urDaddy?! */
static uint8_t key[] = { 0x57, 0x68, 0x6F, 0x31, 0x73, 0x79, 0x30, 0x75,
                         0x72, 0x44, 0x61, 0x64, 0x64, 0x79, 0x3F, 0x21 };
static uint8_t iv[] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

int main( int argc, char **argv )
{
    uint8_t *buffer, i, outkey[64];
    int32_t err, ret;
    uint32_t len;
    unsigned long outlen;
    symmetric_CBC cbc;
    hash_state md;

    /* Set default return code to 1 */
    ret = 1;

    if (argc != 2)
    {
        printf("Usage: %s <base64_passphrase>\n", argv[0]);
        return ret;
    }

    /* Prepare buffer to decode base64 data */
    len = strlen(argv[1]);
    outlen = (len * 4) / 3;
    buffer = (uint8_t*)malloc(outlen * sizeof(uint8_t));
    if (!buffer)
    {
        printf("Could not allocate buffer of size %u\n", outlen);
        return ret;
    }

    if ((err = base64_decode(argv[1], len, buffer, &outlen)) != CRYPT_OK)
    {
        printf("Failed to decode base64 input: %s\n", error_to_string(err));
        free(buffer);
        return ret;
    }

    /* Register hash and cipher for tomcrypt functions */
    register_cipher(&aes_desc);
    register_hash(&sha1_desc);

    /* Perform SHA512 on static key */
    if ((err = sha512_init(&md)) != CRYPT_OK)
    {
        printf("Failed to initialize SHA512 hash: %s\n", error_to_string(err));
        goto clean;
    }

    if ((err = sha512_process(&md, key, AES_KEY_LEN)) != CRYPT_OK)
    {
        printf("Failed to process data for SHA512 hash: %s\n", error_to_string(err));
        goto clean;
    }

    if ((err = sha512_done(&md, outkey)) != CRYPT_OK)
    {
        printf("Failed to obtain SHA512 hash result: %s\n", error_to_string(err));
        goto clean;
    }

    /* Perform AES-128-CBC decryption on data using the calculated key in the previous step */
    err = cbc_start(find_cipher("aes"), iv, outkey, AES_KEY_LEN, 0, &cbc);
    if (err != CRYPT_OK)
    {
        printf("Failed to set up AES CBC: %s\n", error_to_string(err));
        goto clean;
    }

    err = cbc_decrypt(buffer, buffer, outlen, &cbc);
    if (err != CRYPT_OK)
    {
        printf("Failed to decrypt AES data: %s\n", error_to_string(err));
        goto clean;
    }

    /* Remove PKCS#5 padding by hand */
    i = *(uint8_t*)(buffer + outlen - 1);
    if (i < AES_KEY_LEN)
    {
        while (i != 0)
        {
            buffer[outlen - i] = 0;
            i--;
        }
    }

    /* Print result */
    puts("-----------------");
    printf("Decryption: %s\n", buffer);
    puts("-----------------");
    ret = 0;

clean:
    unregister_hash(&sha1_desc);
    unregister_cipher(&aes_desc);
    free(buffer);

    return ret;
}
