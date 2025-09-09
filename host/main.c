#include <err.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include <tee_client_api.h>

#include <remote_attestation.h>


TEEC_Result ta_get_device_id() {
    TEEC_Result res;
    TEEC_Context ctx;
    TEEC_Session sess;
    TEEC_Operation op;
    TEEC_UUID uuid = TA_REMOTE_ATTESTATION_UUID;
    uint32_t err_origin;

    res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS) {
		printf("TEEC_InitializeContext failed with code 0x%x", res);
        return res;
    }

	res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS) {
        printf("TEEC_Opensession failed with code 0x%x origin 0x%x", res, err_origin);
        return res;
    }

	memset(&op, 0, sizeof(op));

    op.paramTypes = TEEC_PARAM_TYPES(
        TEEC_VALUE_OUTPUT,
        TEEC_NONE,
        TEEC_NONE,
        TEEC_NONE
    );

    res = TEEC_InvokeCommand(&sess, TA_REMOTE_ATTESTATION_CMD_GET_DEVICE_ID, &op, &err_origin);
    if (res != TEEC_SUCCESS) {
        printf("TEEC_InvokeCommand failed with code 0x%x, origin 0x%x", res, err_origin);
        return res;
    }

    printf(
        "TA result: %u\n",
        op.params[0].value.a
    );

    TEEC_CloseSession(&sess);
    TEEC_FinalizeContext(&ctx);

    return TEEC_SUCCESS;
}

void test_get_id() {
    TEEC_Result res;
    res = ta_get_device_id();
}



TEEC_Result ta_test_remote() {
    TEEC_Result res;
    TEEC_Context ctx;
    TEEC_Session sess;
    TEEC_Operation op;
    TEEC_UUID uuid = TA_REMOTE_ATTESTATION_UUID;
    uint32_t err_origin;

    if (TEEC_InitializeContext(NULL, &ctx) != TEEC_SUCCESS || TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin) != TEEC_SUCCESS) {
        printf("Error setting up invokation.");
        return res;
    }

    memset(&op, 0, sizeof(op));

    op.paramTypes = TEEC_PARAM_TYPES(
        TEEC_NONE,
        TEEC_NONE,
        TEEC_NONE,
        TEEC_NONE
    );

    res = TEEC_InvokeCommand(&sess, TA_REMOTE_ATTESTATION_CMD_TEST_REMOTE, &op, &err_origin);
    if (res != TEEC_SUCCESS) {
        printf("TEEC_InvokeCommand failed with code 0x%x, origin 0x%x", res, err_origin);
        return res;
    }

    printf("TA result: Ok.\n");

    TEEC_CloseSession(&sess);
    TEEC_FinalizeContext(&ctx);

    return TEEC_SUCCESS;
}

void test_remote() {
    TEEC_Result res;
    res = ta_test_remote();
}



TEEC_Result ta_request_attestation(uint8_t vm_index, char* pattern, size_t pattern_size, size_t mem_region_size) {
    TEEC_Result res;
    TEEC_Context ctx;
    TEEC_Session sess;
    TEEC_Operation op;
    TEEC_UUID uuid = TA_REMOTE_ATTESTATION_UUID;
    uint32_t err_origin;

    res = TEEC_InitializeContext(NULL, &ctx);
    if (res != TEEC_SUCCESS) {
        printf("Error initializing Context: %u\n", res);
        return res;
    }

    res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
    if (res != TEEC_SUCCESS) {
        printf("Error opening Session: %u\n", res);
        return res;
    }

    memset(&op, 0, sizeof(op));

    op.params[0].value.a = vm_index;
    op.params[1].tmpref.buffer = pattern;
    op.params[1].tmpref.size = pattern_size;
    op.params[2].value.a = mem_region_size;

    op.paramTypes = TEEC_PARAM_TYPES(
        TEEC_VALUE_INPUT,
        TEEC_MEMREF_TEMP_INPUT,
        TEEC_VALUE_INPUT,
        TEEC_NONE
    );

    res = TEEC_InvokeCommand(&sess, TA_REMOTE_ATTESTATION_CMD_REQUEST_ATTESTATION, &op, &err_origin);
    if (res != TEEC_SUCCESS) {
        printf("TEEC_InvokeCommand failed with code 0x%x, origin 0x%x", res, err_origin);
        return res;
    }

    printf("TA result: Ok.\n");

    TEEC_CloseSession(&sess);
    TEEC_FinalizeContext(&ctx);

    return TEEC_SUCCESS;
}

void test_request_attestation() {
    TEEC_Result res;

    uint8_t vm_index = 0;
    char pattern[] = { 0x01, 0x02, 0x03 };
    size_t mem_region_size = 8;

    res = ta_request_attestation(vm_index, pattern, sizeof(pattern), mem_region_size);
}


TEEC_Result ta_request_attestation_from_queue() {
    TEEC_Result res;
    TEEC_Context ctx;
    TEEC_Session sess;
    TEEC_Operation op;
    TEEC_UUID uuid = TA_REMOTE_ATTESTATION_UUID;
    uint32_t err_origin;

    res = TEEC_InitializeContext(NULL, &ctx);
    if (res != TEEC_SUCCESS) {
        printf("Error initializing Context: %u\n", res);
        return res;
    }

    res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
    if (res != TEEC_SUCCESS) {
        printf("Error opening Session: %u\n", res);
        return res;
    }

    memset(&op, 0, sizeof(op));

    op.paramTypes = TEEC_PARAM_TYPES(
        TEEC_NONE,
        TEEC_NONE,
        TEEC_NONE,
        TEEC_NONE
    );

    res = TEEC_InvokeCommand(&sess, TA_REMOTE_ATTESTATION_CMD_REQUEST_ATTESTATION_FROM_QUEUE, &op, &err_origin);
    if (res != TEEC_SUCCESS) {
        printf("TEEC_InvokeCommand failed with code 0x%x, origin 0x%x", res, err_origin);
        return res;
    }

    printf("TA result: Ok.\n");

    TEEC_CloseSession(&sess);
    TEEC_FinalizeContext(&ctx);

    return TEEC_SUCCESS;
}

void test_request_attestation_from_queue() {
    TEEC_Result res;
    res = ta_request_attestation_from_queue();
}


void ta_enroll_cert() {
    TEEC_Result res;
    TEEC_Context ctx;
    TEEC_Session sess;
    TEEC_Operation op;
    TEEC_UUID uuid = TA_REMOTE_ATTESTATION_UUID;
    uint32_t err_origin;

    res = TEEC_InitializeContext(NULL, &ctx);
    if (res != TEEC_SUCCESS) {
        printf("Error initializing Context: %u\n", res);
        return res;
    }

    res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
    if (res != TEEC_SUCCESS) {
        printf("Error opening Session: %u\n", res);
        return res;
    }

    memset(&op, 0, sizeof(op));

    op.paramTypes = TEEC_PARAM_TYPES(
        TEEC_NONE,
        TEEC_NONE,
        TEEC_NONE,
        TEEC_NONE
    );

    res = TEEC_InvokeCommand(&sess, TA_REMOTE_ATTESTATION_CMD_ENROLL_CERT, &op, &err_origin);
    if (res != TEEC_SUCCESS) {
        printf("TEEC_InvokeCommand failed with code 0x%x, origin 0x%x", res, err_origin);
        return res;
    }

    printf("TA result: Ok.\n");

    TEEC_CloseSession(&sess);
    TEEC_FinalizeContext(&ctx);

    return TEEC_SUCCESS;
}

void test_enroll() {
    TEEC_Result res;
    res = ta_enroll_cert();
}



int main(int argc, char** argv) {
    if (argc <= 1) {
        printf("No params given. Append either 'id', 'enroll', 'attest', 'queue', or 'test' to this command.\n");
        return 0;
    }

    char* arg = argv[1];

    if (strcmp(arg, "id") == 0) {
        test_get_id();
    } else if (strcmp(arg, "enroll") == 0) {
        test_enroll();
    } else if (strcmp(arg, "attest") == 0) {
        test_request_attestation();
    } else if (strcmp(arg, "queue") == 0) {
        test_request_attestation_from_queue();
    } else if (strcmp(arg, "test") == 0) {
        test_remote();
    } else {
        printf("Invalid parameter(s).\n");
    }

    return 0;
}
