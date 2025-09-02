#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <sys/types.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <tee_isocket.h>
#include <tee_tcpsocket.h>

#include <mbedtls/x509_csr.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/ssl.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/pk.h>
#include <mbedtls/ecp.h>
#include <mbedtls/error.h>
#include <mbedtls/base64.h>

#include <pta_memread.h>

#include "./include/remote_attestation.h"
#include "compiler.h"
#include "tee_api_defines.h"
#include "tee_api_types.h"

#include "storage_handling.h"
#include "certificate_handling.h"
#include "network_handling.h"
#include "command_parser.h"
#include "utils.h"
#include "queue.h"

#include "remote_attestation.h"


TEE_Result enroll_certificate(void) {
    TEE_Result res;

    char buffer[512];
    TEE_MemFill(buffer, 0, sizeof(buffer));

    mbedtls_pk_context key;
    generate_key(&key);

    res = generate_csr((char*) buffer, sizeof(buffer), &key);
    if (res != TEE_SUCCESS)
        return res;

    char command[512];
    TEE_MemFill(command, 0, sizeof(command));
    strncat(command, "ENROLL\n", 7);
    strncat(command, buffer, strlen(buffer));
    strncat(command, "\n\n", 2);

    TEE_MemFill(buffer, 0, sizeof(buffer));
    res = execute_command(command, strlen(command), buffer, sizeof(buffer), false);
    if (res != TEE_SUCCESS)
        return res;
    uint16_t response_length = strlen(buffer);

    uint16_t offset = 0;
    char first_param[8];
    get_next_parameter(buffer, response_length, &offset, first_param, 8, NULL);

    if (first_param[0] != 'S')
        return TEE_ERROR_EXTERNAL_CANCEL;

    TEE_MemFill(command, 0, sizeof(command));
    join_parameters(buffer, response_length, offset, command, sizeof(command));
    offset = strlen(command);
    command[offset] = '\n';
    command[offset + 1] = '\0';

    res = save_certificate_if_is_valid(command);
    if (res != TEE_SUCCESS)
        return res;

    res = save_private_key_to_storage(&key);
    return res;
}


TEE_Result take_measurement(uint8_t vm_index, uint32_t block_index, char* pattern, size_t pattern_size, size_t memory_region_size, char* output_buffer_64bytes) {
    TEE_UUID uuid = PTA_MEMREAD_UUID;
    TEE_TASessionHandle sess;
    uint32_t ret_origin;
    TEE_Result res;

    res = TEE_OpenTASession(&uuid, 0, 0, NULL, &sess, &ret_origin);
    if (res != TEE_SUCCESS)
        return res;

    TEE_Param pta_params[4] = { 0 };

    TEE_MemFill(output_buffer_64bytes, 0, 64);

    pta_params[0].value.a = vm_index;
    pta_params[0].value.b = block_index;
    pta_params[1].memref.buffer = pattern;
    pta_params[1].memref.size = pattern_size;
    pta_params[2].value.a = memory_region_size;
    pta_params[3].memref.buffer = output_buffer_64bytes;
    pta_params[3].memref.size = 64;

    uint32_t param_types = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_VALUE_INPUT,     // VM index
        TEE_PARAM_TYPE_MEMREF_INPUT,    // Pattern
        TEE_PARAM_TYPE_VALUE_INPUT,     // Memory Region size
        TEE_PARAM_TYPE_MEMREF_OUTPUT    // Hashed Value
    );

    res = TEE_InvokeTACommand(
        sess, 0,
        PTA_MEMREAD_CMD_ATTEST_MEMORY,
        param_types, pta_params,
        &ret_origin
    );

    TEE_CloseTASession(sess);

    return res;
}


TEE_Result request_attestation(uint8_t vm_index, uint32_t block_index, char* pattern, size_t pattern_size, size_t memory_region_size) {
    TEE_Result res;
    int ret;
    char measurement[64];
    char encoded_measurement[128];
    char command[256];
    char response[16];

    res = take_measurement(vm_index, block_index, pattern, pattern_size, memory_region_size, measurement);
    if (res != TEE_SUCCESS)
        return res;

    TEE_MemFill(command, 0, sizeof(command));

    size_t olen;
    ret = mbedtls_base64_encode((unsigned char*) encoded_measurement, sizeof(encoded_measurement), &olen, (const unsigned char*) measurement, sizeof(measurement));
    if (ret != 0)
        return ret;

    strncat(command, "ATTEST\n", 7);
    strncat(command, encoded_measurement, olen);
    strncat(command, "\n\n", 2);

    res = execute_command(command, strlen(command), response, sizeof(response), true);


    if (res == TEE_ERROR_COMMUNICATION) {
        queue ctx;
        queue_get_ctx(&ctx);
        res = queue_add(&ctx, command, strlen(command));

        if (res == TEE_SUCCESS)
            res = TEE_ERROR_COMMUNICATION;

        return res;
    }


    if (res != TEE_SUCCESS)
        return res;

    if (response[0] != 'S')
        return TEE_ERROR_EXTERNAL_CANCEL;

    return TEE_SUCCESS;
}


TEE_Result request_attestation_for_queue(void) {
    TEE_Result res;
    char command[256];
    queue ctx;

    bool has_result = false;
    char response[16];
    while (!has_result) {
        res = TEE_Wait(5000);
        if (res != TEE_SUCCESS)
            return res;

        queue_get_ctx(&ctx);

        res = queue_peek(&ctx, command, sizeof(command));

        if (res != TEE_SUCCESS)
            continue;

        res = execute_command(
            command, strlen(command),
            response, sizeof(response),
            true
        );

        if (res == TEE_SUCCESS)
            has_result = true;
    }

    res = queue_step(&ctx);
    if (res != TEE_SUCCESS)
        return res;

    if (response[0] != 'S')
        return TEE_ERROR_EXTERNAL_CANCEL;

    return TEE_SUCCESS;
}


TEE_Result test_remote_connection(void) {
    TEE_Result resp;
    const char* command = "TEST\n\n";

    char resp_buf[64];
    resp = execute_command(command, strlen(command), resp_buf, sizeof(resp_buf), true);

    if (resp != TEE_SUCCESS)
        return resp;

    if (!has_complete_command(resp_buf, sizeof(resp_buf)) || count_params(resp_buf, sizeof(resp_buf), 0) < 2) {
        return TEE_ERROR_BAD_FORMAT;
    }

    return TEE_SUCCESS;
}


/* ***************** */
/* COMMAND FUNCTIONS */
/* ***************** */


TEE_Result command_get_device_id(uint32_t param_types, TEE_Param params[4]) {
    TEE_Result res;

    uint32_t exp_param_types = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_VALUE_OUTPUT,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE
    );

    if (param_types != exp_param_types)
        return TEE_ERROR_BAD_PARAMETERS;

    char buf[4];

    res = get_id(buf);
    if (res != TEE_SUCCESS)
        return res;

    params[0].value.a = (buf[0] << 24) | (buf[1] << 16) | (buf[2] << 8) | buf[3];

    return TEE_SUCCESS;
}


TEE_Result command_enroll_certificate(uint32_t param_types, TEE_Param params[4] __maybe_unused) {
    uint32_t exp_param_types = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE
    );

    if (param_types != exp_param_types)
        return TEE_ERROR_BAD_PARAMETERS;

    return enroll_certificate();
}


TEE_Result command_test_remote(uint32_t param_types, TEE_Param params[4] __maybe_unused) {
    uint32_t exp_param_types = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE
    );

    if (param_types != exp_param_types)
        return TEE_ERROR_BAD_PARAMETERS;

    return test_remote_connection();
}


TEE_Result command_request_attestation(uint32_t param_types, TEE_Param params[4]) {
    uint32_t exp_param_types = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_VALUE_INPUT,
        TEE_PARAM_TYPE_MEMREF_INPUT,
        TEE_PARAM_TYPE_VALUE_INPUT,
        TEE_PARAM_TYPE_NONE
    );

    if (param_types != exp_param_types)
        return TEE_ERROR_BAD_PARAMETERS;

    return request_attestation(
        (uint8_t) params[0].value.a,
        (uint32_t) params[0].value.b,
        params[1].memref.buffer,
        (size_t) params[1].memref.size,
        (size_t) params[2].value.a
    );
}


TEE_Result command_request_attestation_from_queue(uint32_t param_types, TEE_Param params[4] __maybe_unused) {
    uint32_t exp_param_types = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE
    );

    if (param_types != exp_param_types)
        return TEE_ERROR_BAD_PARAMETERS;

    return request_attestation_for_queue();
}



/* ********************** */
/* MANDATORY TA FUNCTIONS */
/* ********************** */


TEE_Result TA_CreateEntryPoint(void) {
    return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void) {
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types, TEE_Param params[4] __maybe_unused, void** sess_ctx __maybe_unused) {
    uint32_t exp_param_types = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE
    );

    if (param_types != exp_param_types)
        return TEE_ERROR_BAD_PARAMETERS;

    return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void* sess_ctx __maybe_unused) {
}

TEE_Result TA_InvokeCommandEntryPoint(void* sess_ctx __maybe_unused, uint32_t cmd_id, uint32_t param_types, TEE_Param params[4]) {
    switch (cmd_id)  {
        case TA_REMOTE_ATTESTATION_CMD_GET_DEVICE_ID:
            return command_get_device_id(param_types, params);
        case TA_REMOTE_ATTESTATION_CMD_ENROLL_CERT:
            return command_enroll_certificate(param_types, params);
        case TA_REMOTE_ATTESTATION_CMD_REQUEST_ATTESTATION:
            return command_request_attestation(param_types, params);
        case TA_REMOTE_ATTESTATION_CMD_REQUEST_ATTESTATION_FROM_QUEUE:
            return command_request_attestation_from_queue(param_types, params);
        case TA_REMOTE_ATTESTATION_CMD_TEST_REMOTE:
            return command_test_remote(param_types, params);
        default:
            return TEE_ERROR_NOT_SUPPORTED;
    };
}
