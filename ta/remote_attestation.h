#ifndef __REMOTE_ATTESTATION_REMOTE_ATTESTATION_H
#define __REMOTE_ATTESTATION_REMOTE_ATTESTATION_H

#include <tee_api_defines.h>
#include <tee_api_types.h>


TEE_Result enroll_certificate(
    void
);


TEE_Result take_measurement(
    uint8_t vm_index,
    uint32_t block_index,
    char* pattern,
    size_t pattern_size,
    size_t memory_region_size,
    char* output_buffer_64bytes
);


TEE_Result request_attestation(
    uint8_t vm_index,
    uint32_t block_index,
    char* pattern,
    size_t pattern_size,
    size_t memory_region_size
);


TEE_Result request_attestation_from_queue(
    void
);


TEE_Result test_remote_connection(
    void
);


/* ******** */
/* COMMANDS */
/* ******** */


TEE_Result command_get_device_id(
    uint32_t param_types,
    TEE_Param params[4]
);


TEE_Result command_enroll_certificate(
    uint32_t param_types,
    TEE_Param params[4]
);


TEE_Result command_test_remote(
    uint32_t param_types,
    TEE_Param params[4]
);


TEE_Result command_request_attestation(
    uint32_t param_types,
    TEE_Param params[4]
);


TEE_Result command_request_attestation_from_queue(
    uint32_t param_types,
    TEE_Param params[4]
);


#endif /* TA_REMOTE_ATTESTATION_REMOTE_ATTESTATION_H */
