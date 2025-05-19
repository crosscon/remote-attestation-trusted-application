#include <err.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include <tee_client_api.h>

#include <remote_attestation.h>


void test_get_id() {
    TEEC_Result res;
    TEEC_Context ctx;
    TEEC_Session sess;
    TEEC_Operation op;
    TEEC_UUID uuid = TA_REMOTE_ATTESTATION_UUID;
    uint32_t err_origin;

    res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS) {
		printf("TEEC_InitializeContext failed with code 0x%x", res);
        return;
    }

	res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS) {
        printf("TEEC_Opensession failed with code 0x%x origin 0x%x", res, err_origin);
        return;
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
        return;
    }

    printf(
        "TA result: %u\n",
        op.params[0].value.a
    );

    TEEC_CloseSession(&sess);
    TEEC_FinalizeContext(&ctx);
}



void test_remote() {
    TEEC_Result res;
    TEEC_Context ctx;
    TEEC_Session sess;
    TEEC_Operation op;
    TEEC_UUID uuid = TA_REMOTE_ATTESTATION_UUID;
    uint32_t err_origin;

    if (TEEC_InitializeContext(NULL, &ctx) != TEEC_SUCCESS || TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin) != TEEC_SUCCESS) {
        printf("Error setting up invokation.");
        return;
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
        return;
    }

    printf("TA result: Ok.\n");

    TEEC_CloseSession(&sess);
    TEEC_FinalizeContext(&ctx);
}



void test_request_attestation() {
    TEEC_Result res;
    TEEC_Context ctx;
    TEEC_Session sess;
    TEEC_Operation op;
    TEEC_UUID uuid = TA_REMOTE_ATTESTATION_UUID;
    uint32_t err_origin;

    res = TEEC_InitializeContext(NULL, &ctx);
    if (res != TEEC_SUCCESS) {
        printf("Error initializing Context: %u\n", res);
        return;
    }

    res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
    if (res != TEEC_SUCCESS) {
        printf("Error opening Session: %u\n", res);
        return;
    }

    memset(&op, 0, sizeof(op));

    uint8_t vm_index = 0;
    char pattern[] = { 0x01, 0x02, 0x03 };
    uint8_t mem_region_size = 3;

    op.params[0].value.a = vm_index;
    op.params[1].tmpref.buffer = pattern;
    op.params[1].tmpref.size = sizeof(pattern);
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
        return;
    }

    printf("TA result: Ok.\n");

    TEEC_CloseSession(&sess);
    TEEC_FinalizeContext(&ctx);
}


void test_request_attestation_from_queue() {
    TEEC_Result res;
    TEEC_Context ctx;
    TEEC_Session sess;
    TEEC_Operation op;
    TEEC_UUID uuid = TA_REMOTE_ATTESTATION_UUID;
    uint32_t err_origin;

    res = TEEC_InitializeContext(NULL, &ctx);
    if (res != TEEC_SUCCESS) {
        printf("Error initializing Context: %u\n", res);
        return;
    }

    res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
    if (res != TEEC_SUCCESS) {
        printf("Error opening Session: %u\n", res);
        return;
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
        return;
    }

    printf("TA result: Ok.\n");

    TEEC_CloseSession(&sess);
    TEEC_FinalizeContext(&ctx);
}



void test_enroll() {
    TEEC_Result res;
    TEEC_Context ctx;
    TEEC_Session sess;
    TEEC_Operation op;
    TEEC_UUID uuid = TA_REMOTE_ATTESTATION_UUID;
    uint32_t err_origin;

    res = TEEC_InitializeContext(NULL, &ctx);
    if (res != TEEC_SUCCESS) {
        printf("Error initializing Context: %u\n", res);
        return;
    }

    res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
    if (res != TEEC_SUCCESS) {
        printf("Error opening Session: %u\n", res);
        return;
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
        return;
    }

    printf("TA result: Ok.\n");

    TEEC_CloseSession(&sess);
    TEEC_FinalizeContext(&ctx);
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
