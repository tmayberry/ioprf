#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#include "psi-lib.h"

/*
  AES256-GCM encryption
  Only for small ciphertexts
  Note: caller must take care of memory management.
  Return:
  Length of ciphertext (>0)
  0 on error
*/
int enc(unsigned char *plaintext, int plaintext_len,
        unsigned char *key, unsigned char *iv,
        unsigned char *ciphertext, unsigned char *tag)
{
    /*
    This function is largely borrowed from:

    https://wiki.openssl.org/index.php/EVP_Authenticated_Encryption_and_Decryption#Authenticated_Encryption_using_GCM_mode

    */

    EVP_CIPHER_CTX *ctx;

    int len;
    int ciphertext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) {
        printf("Unable to initialize OpenSSL context\n");
        return 0;
    }

    /* Initialise the encryption operation. */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
        printf("Unable to initialize OpenSSL context\n");
        return 0;
    }

    if (IV_LENGTH!=12) {
        /* Set IV length if default 12 bytes (96 bits) is not appropriate */
        if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LENGTH, NULL)) {
            printf("Unable to set IV length\n");
            return 0;
        }
    }

    /* Initialise key and IV */
    if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) {
        printf("Unable to initialize encryption key and IV\n");
        return 0;
    }

    /* Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) {
        printf("Unable to encrypt data\n");
        return 0;
    }

    ciphertext_len = len;

    /* Finalise the encryption. Normally ciphertext bytes may be written at
     * this stage, but this does not occur in GCM mode
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
        printf("Unable to complete encryption of data\n");
        return 0;
    }

    ciphertext_len += len;

    /* Get the tag */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AES_BLOCKSIZE, tag)) {
        printf("Unable to acquire encryption tag\n");
        return 0;
    }

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}


/*
  Compute Hash

  Return:
  1 on success
  0 on error
*/
int hash(unsigned char* output, unsigned char *input, unsigned int len) {
    EVP_MD_CTX *ctx;

    if((ctx = EVP_MD_CTX_create()) == NULL)
        return 0;

    if(1 != EVP_DigestInit_ex(ctx, EVP_sha256(), NULL))
        return 0;

    if(1 != EVP_DigestUpdate(ctx, input, len))
        return 0;

    if(KEY_LENGTH != SHA256_DIGEST_LENGTH) {
        printf("Error in updating digest\n");
        return 0;
    }

    unsigned int digest_len = KEY_LENGTH;

    if(1 != EVP_DigestFinal_ex(ctx, output, &digest_len))
        return 0;

    EVP_MD_CTX_destroy(ctx);

    return 1;
}



/*

  AES256-GCM decryption
  Only for small ciphertexts
  Note: caller must take care of memory management.
  Return:
  >0 success
  -1 in case verification fails
  0 on error
*/
int dec(unsigned char *ciphertext, int ciphertext_len, unsigned char *tag, unsigned char *key, unsigned char *iv,
        unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    int ret;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) {
        printf("Unable to initialize OpenSSL context\n");
        return 0;
    }

    /* Initialise the decryption operation. */
    if(!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
        printf("Unable initiate decryption operation\n");
        return 0;
    }

    if(IV_LENGTH!=12) {
        /* Set IV length. Not necessary if this is 12 bytes (96 bits) */
        if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LENGTH, NULL)) {
            printf("Unable set IV length\n");
            return 0;
        }
    }

    /* Initialise key and IV */
    if(!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)) {
        printf("Unable to initialize key and IV\n");
        return 0;
    }

    /* Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary
     */
    if(!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
        printf("Unable to decrypt\n");
        return 0;
    }

    plaintext_len = len;

    /* Set expected tag value. Works in OpenSSL 1.0.1d and later */
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AES_BLOCKSIZE, tag)) {
        printf("Unable set tag value\n");
        return 0;
    }

    /* Finalise the decryption. A positive return value indicates success,
     * anything else is a failure - the plaintext is not trustworthy.
     */
    ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
    if(ret > 0) {
        /* Success */
        plaintext_len += len;
        return plaintext_len;
    }
    else {
        /* Verify failed */
        return -1;
    }
}

