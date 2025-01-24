#include <string.h>
#include <wolfssl/wolfcrypt/sha3.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/ed25519.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/pwdbased.h>
#include <wolfssl/wolfcrypt/aes.h>
#include "esp_timer.h"

static const char *const BTAG = "Benchmark";

void printHex(char *varName, const unsigned char *bytes, size_t length)
{
    char hexString[length * 2 + 1]; // Allocate space for hex string
    for (size_t i = 0; i < length; i++)
    {
        sprintf(hexString + (i * 2), "%02x", bytes[i]);
    }
    hexString[length * 2] = '\0';                 // Null-terminate the string
    ESP_LOGI(BTAG, "%s: %s", varName, hexString); // Log the hex string
}

void gen_random()
{
    RNG rng;
    byte block[32];
    wc_InitRng(&rng);

    wc_RNG_GenerateBlock(&rng, block, 32);
    printHex("random", block, 32);
}

// TODO: move free outsize of benchmark
void sha3_256(byte in1[32], byte in2[32], byte out[32]) // out = Hash(in1 + in2)
{
    byte inputData[64];
    memcpy(inputData, in1, 32);
    memcpy(inputData + 32, in2, 32);

    int ret;
    wc_Sha3 sha3;
    ret = wc_InitSha3_256(&sha3, NULL, INVALID_DEVID);
    if (ret != 0)
    {
        ESP_LOGI(BTAG, "wc_InitSha3_256 failed");
    }
    else
    {
        wc_Sha3_256_Update(&sha3, inputData, sizeof(inputData));
        wc_Sha3_256_Final(&sha3, out);
        wc_Sha3_256_Free(&sha3);
    }
}

void sign_ed25519(ed25519_key *key, byte *message, int messageSz, byte sig[64])
{
    int ret;
    word32 sigSz = 64;
    ret = wc_ed25519_sign_msg(message, messageSz, sig, &sigSz, key);
    if (ret != 0)
    {
        ESP_LOGI(BTAG, "wc_ed25519_sign_msg failed %d", ret);
    }
}

void sign_ed25519_from_private_key()
{
    RNG rng;
    byte priv[32];
    wc_InitRng(&rng);
    wc_RNG_GenerateBlock(&rng, priv, 32);
    printHex("priv", priv, 32);

    int ret;

    ed25519_key key;
    wc_ed25519_init(&key); // initialize key
    ret = wc_ed25519_import_private_only(priv, sizeof(priv), &key);
    if (ret != 0)
    {
        ESP_LOGI(BTAG, "wc_ed25519_import_private_only failed");
    }
    printHex("key", &key, sizeof(key));

    byte pub[32];
    word32 pubSz = sizeof(pub);
    ret = wc_ed25519_make_public(&key, pub, pubSz);
    if (ret != 0)
    {
        ESP_LOGI(BTAG, "wc_ed25519_make_public failed %d", ret);
    }
    printHex("key", &key, sizeof(key));

    byte sig[64]; // will hold generated signature
    word32 sigSz = sizeof(sig);
    const char *helloWorld = "Hello, world!";
    byte *message = (byte *)helloWorld;

    ret = wc_ed25519_sign_msg(message, sizeof(message), sig, &sigSz, &key);
    if (ret != 0)
    {
        ESP_LOGI(BTAG, "wc_ed25519_sign_msg failed %d", ret);
    }
    printHex("sig 1", sig, 64);

    ret = wc_ed25519_import_public(pub, sizeof(pub), &key);
    if (ret != 0)
    {
        ESP_LOGI(BTAG, "wc_ed25519_import_public failed %d", ret);
    }
    printHex("key", &key, sizeof(key));

    byte sig2[64]; // will hold generated signature
    word32 sigSz2 = sizeof(sig2);
    ret = wc_ed25519_sign_msg(message, sizeof(message), sig2, &sigSz2, &key);
    if (ret != 0)
    {
        ESP_LOGI(BTAG, "wc_ed25519_sign_msg failed %d", ret);
    }
    printHex("sig 2", sig, 64); // ok, same as sig 1
}

void create_ed25519_from_private_key(ed25519_key *key, byte priv[32], byte pub[32])
{
    int ret;
    ret = wc_ed25519_import_private_only(priv, 32, key);
    if (ret != 0)
    {
        ESP_LOGI(BTAG, "wc_ed25519_import_private_only failed %d", ret);
        ESP_LOGI(BTAG, "wc_ed25519_import_private_only failed error: %s", wc_GetErrorString(ret));
        return;
    }
    ret = wc_ed25519_make_public(key, pub, 32);
    if (ret != 0)
    {
        ESP_LOGI(BTAG, "wc_ed25519_make_public failed %d", ret);
        ESP_LOGI(BTAG, "wc_ed25519_make_public failed error: %s", wc_GetErrorString(ret));
        return;
    }
}

unsigned char pubkeyder[] = {
    0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00, 0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00, 0x9a, 0x2c, 0x50, 0xfc, 0x0f, 0x33, 0x58, 0x76, 0x3b, 0x26, 0x2c, 0xdf, 0xba, 0x27, 0x14, 0x80, 0xcd, 0x34, 0xec, 0x9f, 0xd9, 0xcb, 0x25, 0xe3, 0xe0, 0x1e, 0xdd, 0x5b, 0xc3, 0xf8, 0xa6, 0xbe, 0xf4, 0xf6, 0x11, 0x83, 0xf7, 0x55, 0x1d, 0xf1, 0x8d, 0x89, 0x96, 0xf6, 0xed, 0x22, 0xf6, 0xbf, 0x79, 0x4b, 0xec, 0x7f, 0x9e, 0xbf, 0x77, 0x2a, 0x84, 0x16, 0xc2, 0xef, 0x55, 0x5f, 0x04, 0xe5, 0x8c, 0x21, 0x65, 0x50, 0x03, 0x39, 0xaf, 0xba, 0x4b, 0x23, 0xc5, 0xdf, 0x82, 0xf2, 0x65, 0x3a, 0x43, 0x75, 0x55, 0x53, 0xf9, 0x7a, 0xf1, 0xf3, 0xa9, 0xf8, 0xa6, 0x55, 0xd4, 0x77, 0x0e, 0xe1, 0xba, 0xe6, 0xa4, 0x4c, 0x07, 0x7c, 0x55, 0x06, 0x9a, 0x96, 0x14, 0x24, 0xca, 0x1e, 0x3d, 0x24, 0xe0, 0x7a, 0xe4, 0x36, 0xe2, 0xa9, 0x32, 0xdf, 0xd3, 0x18, 0xd9, 0xd1, 0x2b, 0x30, 0xa3, 0x62, 0x11, 0x8d, 0x20, 0x38, 0x46, 0x64, 0x75, 0xfa, 0x90, 0x36, 0x24, 0x45, 0x08, 0x91, 0xf0, 0xb5, 0x21, 0x23, 0x63, 0xab, 0xe4, 0x12, 0x81, 0x6d, 0x7f, 0xc9, 0x1f, 0x0c, 0xa3, 0x2e, 0x1d, 0x51, 0x8b, 0xc8, 0x29, 0x5e, 0xfb, 0x1e, 0x98, 0x26, 0x74, 0x98, 0xbf, 0x1d, 0xd1, 0x38, 0x34, 0x3b, 0x69, 0xb9, 0x46, 0x96, 0xaf, 0x12, 0x43, 0x35, 0x5f, 0x64, 0xb2, 0x96, 0x85, 0xdb, 0x45, 0xfe, 0x72, 0x0d, 0xc7, 0x47, 0xe8, 0xec, 0x41, 0x74, 0x2c, 0xfa, 0xc4, 0xbe, 0x09, 0x02, 0xb3, 0x73, 0x14, 0x25, 0x93, 0xcf, 0xa5, 0xc9, 0x97, 0xb0, 0xb2, 0x6c, 0x4d, 0x97, 0x87, 0x37, 0x79, 0xf8, 0x99, 0x41, 0x8b, 0xa4, 0x0d, 0x09, 0x54, 0x8a, 0x14, 0x1d, 0xce, 0xf1, 0x39, 0xb6, 0xd5, 0x0d, 0x22, 0xb7, 0x68, 0x1e, 0xb0, 0x27, 0xa0, 0x5f, 0xa9, 0x45, 0x50, 0xe8, 0x17, 0xb0, 0x1b, 0x7b, 0x02, 0x03, 0x01, 0x00, 0x01};

// TODO: move free outsize of benchmark
void rsa_public_enc(byte *message, int messageSz, byte ciphertext[256], RNG *rng)
{
    RsaKey pub;
    word32 idx = 0;
    int ret = 0;

    wc_InitRsaKey(&pub, NULL); // not using heap hint. No custom memory
    ret = wc_RsaPublicKeyDecode(pubkeyder, &idx, &pub, sizeof(pubkeyder));
    if (ret != 0)
    {
        ESP_LOGI(BTAG, "wc_RsaPublicKeyDecode failed %d", ret);
    }

    ret = wc_RsaPublicEncrypt(message, messageSz, ciphertext, 256, &pub, rng);
    if (ret < 0)
    {
        ESP_LOGI(BTAG, "wc_RsaPublicEncrypt failed %d", ret);
        ESP_LOGI(BTAG, "wc_RsaPublicEncrypt failed error: %s", wc_GetErrorString(ret));
    }
    wc_FreeRsaKey(&pub);
}

WOLFSSL_SMALL_STACK_STATIC const byte salt32[] = {
    0x78, 0x57, 0x8E, 0x5a, 0x5d, 0x63, 0xcb, 0x06,
    0x78, 0x57, 0x8E, 0x5a, 0x5d, 0x63, 0xcb, 0x06,
    0x78, 0x57, 0x8E, 0x5a, 0x5d, 0x63, 0xcb, 0x06,
    0x78, 0x57, 0x8E, 0x5a, 0x5d, 0x63, 0xcb, 0x06}; // a random salt

void kdf(byte *derived, int derivedSz, const byte *pass, int passSz)
{
    int ret;
    ret = wc_PBKDF2(derived, pass, passSz, salt32, (int)sizeof(salt32), 1000, derivedSz, WC_SHA256);
    if (ret != 0)
    {
        ESP_LOGI(BTAG, "wc_PBKDF2 failed %d", ret);
        ESP_LOGI(BTAG, "wc_PBKDF2 failed error: %s", wc_GetErrorString(ret));
    }
}

// TODO: move free outsize of benchmark
void aes(byte *message, byte *cipher, int size, byte *key, byte *iv) // size should be multiple of 16 bytes
{
    Aes enc;
    int ret = 0;
    ret = wc_AesInit(&enc, NULL, INVALID_DEVID);
    if (ret != 0)
    {
        ESP_LOGI(BTAG, "wc_AesInit failed %d", ret);
        ESP_LOGI(BTAG, "wc_AesInit failed error: %s", wc_GetErrorString(ret));
    }
    ret = wc_AesSetKey(&enc, key, AES_BLOCK_SIZE, iv, AES_ENCRYPTION);
    if (ret != 0)
    {
        ESP_LOGI(BTAG, "wc_AesSetKey failed %d", ret);
        ESP_LOGI(BTAG, "wc_AesSetKey failed error: %s", wc_GetErrorString(ret));
    }
    
    ret = wc_AesCbcEncrypt(&enc, cipher, message, size);
    if (ret != 0)
    {
        ESP_LOGI(BTAG, "wc_AesCbcEncrypt failed %d", ret);
        ESP_LOGI(BTAG, "wc_AesCbcEncrypt failed error: %s", wc_GetErrorString(ret));
    }
    wc_AesFree(&enc);
}

void run_benchmark(uint sizeOfData)
{
    // init
    RNG rng;
    wc_InitRng(&rng);
    const char *e_i_1_kdfpass = "EventSecret,1,1";
    const char *e_i_2_kdfpass = "EventSecret,1,2";
    const char *e_i_3_kdfpass = "EventSecret,1,3";
    byte e_i_1_prekey[32];
    byte e_i_2_prekey[32];
    byte e_i_3_prekey[32];
    ed25519_key e_i_1_key;
    ed25519_key e_i_2_key;
    ed25519_key e_i_3_key;
    wc_ed25519_init(&e_i_1_key);
    wc_ed25519_init(&e_i_2_key);
    wc_ed25519_init(&e_i_3_key);
    byte m_1_aes_key_and_iv[32+16];
    byte m_2_aes_key_and_iv[32+16];
    byte m_3_aes_key_and_iv[32+16];
    // byte m_1_rsa_encrypted_key[256];
    byte r_2_hash_result[32];
    // byte m_1_aes_encrypted_data[1040];

    // messages
    struct M3SignData
    {
        byte data[sizeOfData]; // 32
        char s_3_address[16];
    };
    struct M3
    {
        struct M3SignData m3SignData;
        byte e_i_3_public_key[32];
        byte ms_3[32];
        byte m_3_signature[64];
    };
    struct M3 *m3 = malloc(sizeof(struct M3));

    struct M2
    {
        byte m_3_aes_encrypted_data[sizeof(m3) + 16]; // its size can change (size of M3 + 16 - (size of M3 mod 16))
        byte m_3_rsa_encrypted_key[256];
        char s_3_address[16];
        byte e_i_2_public_key[32];
        byte ms_2[32];
        byte ms_2_2[32];
        byte m_2_signature[64];
    };
    struct M2 *m2 = malloc(sizeof(struct M2));
    struct M2SignData
    {
        byte tv_2_hash_result[32];
        char s_2_address[16];
    };
    struct M2SignData *m2SignData = malloc(sizeof(struct M2SignData));

    struct M1
    {
        byte m_2_aes_encrypted_data[sizeof(m2) + 16]; // its size can change (size of M2 + 16 - (size of M2 mod 16))
        byte m_2_rsa_encrypted_key[256];
        char s_2_address[16];
        byte e_i_1_public_key[32];
        byte ms_1[32];
        byte m_1_signature[64];
    };
    struct M1 *m1 = malloc(sizeof(struct M1));
    struct M1SignData
    {
        byte tv_1_hash_result[32];
        char s_1_address[16];
    };
    struct M1SignData *m1SignData = malloc(sizeof(struct M1SignData));
    
    ESP_LOGI(BTAG, "data size: %d bytes", sizeof(m3->m3SignData.data));

    // preparation (can be done in advance when device is idle)
    uint64_t preparationStartTime = esp_timer_get_time();
    kdf(e_i_1_prekey, sizeof(e_i_1_prekey), (const byte *)e_i_1_kdfpass, sizeof(e_i_1_kdfpass));
    kdf(e_i_2_prekey, sizeof(e_i_2_prekey), (const byte *)e_i_2_kdfpass, sizeof(e_i_2_kdfpass));
    kdf(e_i_3_prekey, sizeof(e_i_3_prekey), (const byte *)e_i_3_kdfpass, sizeof(e_i_3_kdfpass));
    // uint64_t preparationTime1 = esp_timer_get_time(); // 174,475μs
    create_ed25519_from_private_key(&e_i_1_key, e_i_1_prekey, m1->e_i_1_public_key);
    create_ed25519_from_private_key(&e_i_2_key, e_i_2_prekey, m2->e_i_2_public_key);
    create_ed25519_from_private_key(&e_i_3_key, e_i_3_prekey, m3->e_i_3_public_key);
    // uint64_t preparationTime2 = esp_timer_get_time(); // 64,539μs
    wc_RNG_GenerateBlock(&rng, m1->ms_1, 32);
    wc_RNG_GenerateBlock(&rng, m2->ms_2, 32);
    wc_RNG_GenerateBlock(&rng, m2->ms_2_2, 32);
    wc_RNG_GenerateBlock(&rng, m3->ms_3, 32);
    wc_RNG_GenerateBlock(&rng, m_1_aes_key_and_iv, 32 + 16);
    wc_RNG_GenerateBlock(&rng, m_2_aes_key_and_iv, 32 + 16);
    wc_RNG_GenerateBlock(&rng, m_3_aes_key_and_iv, 32 + 16);
    // uint64_t preparationTime3 = esp_timer_get_time(); // 1,594μs
    // rsa_public_enc(m_1_aes_key_and_iv, 32 + 16, m_1_rsa_encrypted_key, &rng);
    rsa_public_enc(m_2_aes_key_and_iv, 32 + 16, m1->m_2_rsa_encrypted_key, &rng);
    rsa_public_enc(m_3_aes_key_and_iv, 32 + 16, m2->m_3_rsa_encrypted_key, &rng);
    // uint64_t preparationTime4 = esp_timer_get_time(); // 159,398μs
    snprintf(m2->s_3_address, sizeof(m2->s_3_address), "server 3");
    snprintf(m1->s_2_address, sizeof(m1->s_2_address), "server 2");
    snprintf(m3->m3SignData.s_3_address, sizeof(m3->m3SignData.s_3_address), "server 3");
    snprintf(m2SignData->s_2_address, sizeof(m2SignData->s_2_address), "server 2");
    snprintf(m1SignData->s_1_address, sizeof(m1SignData->s_1_address), "server 1");
    uint64_t preparationEndTime = esp_timer_get_time(); // 33μs
    ESP_LOGI(BTAG, "preparation elapsed: %lluμs | start: %lluμs | end: %lluμs", 
        preparationEndTime - preparationStartTime, preparationStartTime, preparationEndTime);
    // ESP_LOGI(BTAG, "preparation 1: %lluμs | 2: %lluμs | 3: %lluμs | 4: %lluμs,  | 5: %lluμs", 
    //     preparationTime1 - preparationStartTime, 
    //     preparationTime2 - preparationTime1,
    //     preparationTime3 - preparationTime2,
    //     preparationTime4 - preparationTime3,
    //     preparationEndTime - preparationTime4);

    // generate ramdom data to send
    wc_RNG_GenerateBlock(&rng, m3->m3SignData.data, sizeof(m3->m3SignData.data));

    // sending a new event
    uint64_t sendingDataStartTime = esp_timer_get_time();
    // snprintf(m3->m3SignData.data, sizeof(m3->m3SignData.data), "Temperature is 26°C");

    byte *m3SignData_bytes = malloc(sizeof(m3->m3SignData));
    memcpy(m3SignData_bytes, &m3->m3SignData, sizeof(m3->m3SignData));
    sign_ed25519(&e_i_3_key, m3SignData_bytes, sizeof(m3SignData_bytes), m3->m_3_signature);

    byte *m3_bytes = malloc(sizeof(m3));
    memcpy(m3_bytes, &m3, sizeof(m3));
    aes(m3_bytes, m2->m_3_aes_encrypted_data, sizeof(m3_bytes), m_3_aes_key_and_iv, m_3_aes_key_and_iv + 32);
    
    sha3_256(m3->ms_3, m2->ms_2, m2SignData->tv_2_hash_result);

    byte *m2SignData_bytes = malloc(sizeof(m2SignData));
    memcpy(m2SignData_bytes, &m2SignData, sizeof(m2SignData));
    sign_ed25519(&e_i_2_key, m2SignData_bytes, sizeof(m2SignData_bytes), m2->m_2_signature);

    byte *m2_bytes = malloc(sizeof(m2));
    memcpy(m2_bytes, &m2, sizeof(m2));
    aes(m2_bytes, m1->m_2_aes_encrypted_data, sizeof(m2_bytes), m_2_aes_key_and_iv, m_2_aes_key_and_iv + 32);
    
    sha3_256(m3->ms_3, m2->ms_2_2, r_2_hash_result);
    sha3_256(r_2_hash_result, m1->ms_1, m1SignData->tv_1_hash_result);

    byte *m1SignData_bytes = malloc(sizeof(m1SignData));
    memcpy(m1SignData_bytes, &m1SignData, sizeof(m1SignData));
    sign_ed25519(&e_i_1_key, m1SignData_bytes, sizeof(m1SignData_bytes), m1->m_1_signature);

    // byte m1_bytes[sizeof(m1)];
    // memcpy(m1_bytes, &m1, sizeof(m1));
    // aes(m1_bytes, m_1_aes_encrypted_data, sizeof(m1_bytes), m_1_aes_key_and_iv, m_1_aes_key_and_iv + 32);

    uint64_t sendingDataEndTime = esp_timer_get_time();
    ESP_LOGI(BTAG, "sendingData elapsed: %lluμs | start: %lluμs | end: %lluμs", 
        sendingDataEndTime - sendingDataStartTime, sendingDataStartTime, sendingDataEndTime);

    // deinit
    wc_ed25519_free(&e_i_1_key);
    wc_ed25519_free(&e_i_2_key);
    wc_ed25519_free(&e_i_3_key);
    free(m1);
    free(m2);
    free(m3);
    free(m1SignData);
    free(m2SignData);
    free(m3SignData_bytes);
    free(m3_bytes);
    free(m2SignData_bytes);
    free(m2_bytes);
    free(m1SignData_bytes);
}
