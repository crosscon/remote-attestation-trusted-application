#include <stdint.h>
#include <string.h>

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <tee_isocket.h>
#include <tee_tcpsocket.h>

#include <mbedtls/net_sockets.h>

#include "remote_attestation_config.h"
#include "certificate_handling.h"
#include "network_handling.h"
#include "command_parser.h"
#include "tee_api_defines.h"


const char* REMOTE_ATTESTATION_SERVER_SSL_CERT = "-----BEGIN CERTIFICATE-----\n"
    "MIIBNDCB2qADAgECAhQY19+dLiLabpFDinhJt1Sufl6r4DAKBggqhkjOPQQDAjAa\n"
    "MRgwFgYDVQQDDA9yZW1vdGUtdmVyaWZpZXIwHhcNMjUwNDE2MTkwNjUyWhcNMzUw\n"
    "NDE0MTkwNjUyWjAaMRgwFgYDVQQDDA9yZW1vdGUtdmVyaWZpZXIwWTATBgcqhkjO\n"
    "PQIBBggqhkjOPQMBBwNCAARsE/M6YcGB0O+HmGymuj1OfV7w2BlGuR7ybkOSjkZF\n"
    "ITpftsNpaUzQkkVvSnLSYFLzEHPwzoS59b3MRiMOQ+G5MAoGCCqGSM49BAMCA0kA\n"
    "MEYCIQDCws20u2KOuEya5N7I5fC6U1GvfFSyNJarvm5+J7ebiwIhAPgFcmgctAao\n"
    "6NY6e6OIxT+Sy7rVH6E0DmyfNiUYEExV\n"
    "-----END CERTIFICATE-----\n";



int get_random_data_for_mbedtls(void* ctx __unused, unsigned char* output, size_t output_length) {
    TEE_GenerateRandom(output, output_length);
    return 0;
}


int wrapped_send(void* ctx, const unsigned char* buf, size_t len) {
    uint32_t l = len;
    TEE_iSocketHandle ctx_conv = *(TEE_iSocketHandle*) ctx;
    TEE_Result res = TEE_tcpSocket->send(ctx_conv, buf, &l, 10000);

    if (res != TEE_SUCCESS)
        return MBEDTLS_ERR_NET_SEND_FAILED;

    return (int) l;
}


int wrapped_recv(void* ctx, unsigned char* buf, size_t len) {
    uint32_t l = len;
    TEE_iSocketHandle ctx_conv = *(TEE_iSocketHandle*) ctx;
    TEE_Result res = TEE_tcpSocket->recv(ctx_conv, buf, &l, 10000);

    if (res == TEE_ERROR_TIMEOUT)
        return MBEDTLS_ERR_SSL_TIMEOUT;
    else if (res != TEE_SUCCESS)
        return MBEDTLS_ERR_NET_RECV_FAILED;

    return (int) l;
}


TEE_Result execute_command(const char* command, uint16_t command_length, char* response_buffer, uint16_t response_buffer_length, uint8_t use_client_certificate) {
    TEE_Result res;
    int ret;
    uint32_t tcp_err;

    struct socket_ctx tcp_ctx;
    TEE_iSocketHandle tcp_ctx_c = (TEE_iSocketHandle) &tcp_ctx;

    mbedtls_ssl_context ssl_ctx;
    mbedtls_ssl_config ssl_conf;
    mbedtls_x509_crt ca_cert;
    mbedtls_x509_crt client_cert;
    mbedtls_pk_context client_key;

    struct TEE_tcpSocket_Setup_s tcp_conf;
    tcp_conf.ipVersion = TEE_IP_VERSION_4;
    tcp_conf.server_addr = REMOTE_ATTESTATION_SERVER_HOST;
    tcp_conf.server_port = REMOTE_ATTESTATION_SERVER_PORT;

    mbedtls_ssl_init(&ssl_ctx);
    mbedtls_ssl_config_init(&ssl_conf);
    mbedtls_x509_crt_init(&ca_cert);

    if (use_client_certificate) {
        res = load_private_key_from_storage(&client_key);
        if (res != TEE_SUCCESS) {
            res = TEE_ERROR_GENERIC;
            goto clean_data;
        }
        res = load_client_cert_from_storage(&client_cert);
        if (res != TEE_SUCCESS) {
            res = TEE_ERROR_GENERIC;
            goto clean_data;
        }
    }

    mbedtls_ssl_config_defaults(
        &ssl_conf,
        MBEDTLS_SSL_IS_CLIENT,
        MBEDTLS_SSL_TRANSPORT_STREAM,
        MBEDTLS_SSL_PRESET_DEFAULT
    );
    mbedtls_ssl_conf_authmode(&ssl_conf, MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ssl_conf_ca_chain(&ssl_conf, &ca_cert, NULL);
    mbedtls_ssl_conf_rng(&ssl_conf, get_random_data_for_mbedtls, NULL);
    mbedtls_ssl_conf_min_version(&ssl_conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);
    mbedtls_ssl_conf_max_version(&ssl_conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);
    if (use_client_certificate && mbedtls_ssl_conf_own_cert(&ssl_conf, &client_cert, &client_key) != 0) {
        res = TEE_ERROR_ITEM_NOT_FOUND;
        goto clean_data;
    }

    mbedtls_ssl_setup(&ssl_ctx, &ssl_conf);
    mbedtls_ssl_set_bio(&ssl_ctx, &tcp_ctx_c, wrapped_send, wrapped_recv, NULL);

    ret = mbedtls_x509_crt_parse(&ca_cert, (const unsigned char*) REMOTE_ATTESTATION_SERVER_SSL_CERT, strlen(REMOTE_ATTESTATION_SERVER_SSL_CERT) + 1);
    if (ret < 0)
        return TEE_ERROR_BAD_FORMAT;

    res = TEE_tcpSocket->open(&tcp_ctx_c, &tcp_conf, &tcp_err);
    if (res != TEE_SUCCESS)
        goto clean;

    while ((ret = mbedtls_ssl_handshake(&ssl_ctx)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE)  {
            res = TEE_ERROR_BAD_FORMAT;
            goto clean;
        }
    }

    ret = mbedtls_ssl_write(&ssl_ctx, (const unsigned char*) command, command_length);
    if (ret < 0) {
        res = TEE_ERROR_BAD_STATE;
        goto clean;
    }

    uint16_t cumulatively_read = 0;
    char temp_buffer[512];
    char* current_write_position = response_buffer;
    while (cumulatively_read < response_buffer_length && !has_complete_command((const char*) response_buffer, response_buffer_length)) {
        ret = mbedtls_ssl_read(&ssl_ctx, (unsigned char*) temp_buffer, 512);
        if (ret < 0) {
            res = TEE_ERROR_BAD_STATE;
            goto clean;
        }

        TEE_MemMove(current_write_position, temp_buffer, cumulatively_read + ret > response_buffer_length ? response_buffer_length - cumulatively_read - 1 : ret);
        current_write_position += ret;
        cumulatively_read += ret;
    }

    mbedtls_ssl_close_notify(&ssl_ctx);
clean:
    TEE_tcpSocket->close(tcp_ctx_c);
clean_data:

    mbedtls_ssl_free(&ssl_ctx);
    mbedtls_ssl_config_free(&ssl_conf);
    mbedtls_x509_crt_free(&ca_cert);

    return res;
}
