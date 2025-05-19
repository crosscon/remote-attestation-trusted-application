#ifndef __REMOTE_ATTESTATION_NETWORK_HANDLING_H
#define __REMOTE_ATTESTATION_NETWORK_HANDLING_H


#include <stdint.h>
#include <tee_internal_api.h>

#include "remote_attestation_config.h"
#include "certificate_handling.h"


struct socket_ctx {
    uint32_t handle;
    uint32_t proto_error;
};


int get_random_data_for_mbedtls(
    void* ctx __unused,
    unsigned char* output,
    size_t output_length
);


int wrapped_send(
    void* ctx,
    const unsigned char* buf,
    size_t len
);


int wrapped_recv(
    void* ctx,
    unsigned char* buf,
    size_t len
);


TEE_Result execute_command(
    const char* command,
    uint16_t command_length,
    char* response_buffer,
    uint16_t response_buffer_length,
    uint8_t use_client_certificate
);


#endif
