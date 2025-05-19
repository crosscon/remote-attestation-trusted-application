#ifndef __REMOTE_ATTESTATION_CERTIFICATE_HANDLING_H
#define __REMOTE_ATTESTATION_CERTIFICATE_HANDLING_H


#include <mbedtls/x509_csr.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/pk.h>
#include <mbedtls/ecp.h>
#include <mbedtls/error.h>

#include "storage_handling.h"
#include "utils.h"
//#include "remote_attestation_config.h"


/*int get_random_data_for_mbedtls(
    void* ctx,
    unsigned char* output,
    size_t output_length
);*/


TEE_Result load_private_key_from_storage(
    mbedtls_pk_context* key
);


TEE_Result save_private_key_to_storage(
    mbedtls_pk_context* key
);


TEE_Result load_client_cert_from_storage(
    mbedtls_x509_crt* crt
);


TEE_Result save_client_certificate_to_storage(
    mbedtls_x509_crt* crt
);


TEE_Result generate_key(
    mbedtls_pk_context* key
);


TEE_Result get_subject_name(
    char* buffer,
    size_t buffer_length
);


TEE_Result generate_csr(
    char* buffer,
    size_t buffer_length,
    mbedtls_pk_context* key
);


TEE_Result test_if_certificate_is_valid(
    char* pem_certificate
);


TEE_Result save_certificate_if_is_valid(
    char* pem_certificate
);


#endif
