#include <string.h>

#include <tee_internal_api.h>
#include <tee_api_defines.h>
#include <tee_api_types.h>

#include "storage_handling.h"
#include "utils.h"

#include "queue.h"



TEE_Result queue_get_ctx(queue* ctx) {
    TEE_Result res;
    uint8_t next_read = 0;
    uint8_t next_write = 0;

    res = read_object_if_exists(
        REMOTE_ATTESTATION_QUEUE_SECSTORE_NR, strlen(REMOTE_ATTESTATION_QUEUE_SECSTORE_NR),
        (char*) (&next_read), 1
    );
    if (res == TEE_ERROR_ITEM_NOT_FOUND) {
        next_read = 0;
        res = write_object(
            REMOTE_ATTESTATION_QUEUE_SECSTORE_NR, strlen(REMOTE_ATTESTATION_QUEUE_SECSTORE_NR),
            (char*) &next_read, 1
        );
        if (res != TEE_SUCCESS)
            return res;
    } else if (res != TEE_SUCCESS) {
        return res;
    }

    res = read_object_if_exists(
        REMOTE_ATTESTATION_QUEUE_SECSTORE_NW, strlen(REMOTE_ATTESTATION_QUEUE_SECSTORE_NW),
        (char*) &next_write, 1
    );
    if (res == TEE_ERROR_ITEM_NOT_FOUND) {
        next_write = 0;
        res = write_object(
            REMOTE_ATTESTATION_QUEUE_SECSTORE_NW, strlen(REMOTE_ATTESTATION_QUEUE_SECSTORE_NW),
            (char*) &next_write, 1
        );
        if (res != TEE_SUCCESS)
            return res;
    } else if (res != TEE_SUCCESS) {
        return res;
    }

    ctx->next_read = next_read;
    ctx->next_write = next_write;

    return TEE_SUCCESS;
}


uint8_t queue_has_next(queue* ctx) {
    return queue_size(ctx) > 0;
}


uint8_t queue_full(queue* ctx) {
    return (ctx->next_write + 1) % REMOTE_ATTESTATION_QUEUE_MAX_SIZE == ctx->next_read;
}


uint8_t queue_size(queue* ctx) {
    return ctx->next_write >= ctx->next_read
        ? ctx->next_write - ctx->next_read
        : REMOTE_ATTESTATION_QUEUE_MAX_SIZE - (ctx->next_read - ctx->next_write);
}


TEE_Result queue_step(queue* ctx) {
    TEE_Result res;
    res = TEE_SUCCESS;
    if (queue_size(ctx) > 0) {
        uint8_t value = (ctx->next_read + 1) % REMOTE_ATTESTATION_QUEUE_MAX_SIZE;
        res = write_object(
            REMOTE_ATTESTATION_QUEUE_SECSTORE_NR, strlen(REMOTE_ATTESTATION_QUEUE_SECSTORE_NR),
            (char*) &value, 1
        );

        if (res == TEE_SUCCESS)
            ctx->next_read = value;
    }

    return res;
}


TEE_Result queue_peek(queue* ctx, char* buffer, size_t buffer_size) {
    TEE_Result res;
    if (queue_size(ctx) == 0)
        return TEE_ERROR_ITEM_NOT_FOUND;

    char name[16];
    TEE_MemFill(name, 0, sizeof(name));
    uint8_t next_read = ctx->next_read;
    strncat(name, REMOTE_ATTESTATION_QUEUE_SECSTORE_PREF, strlen(REMOTE_ATTESTATION_QUEUE_SECSTORE_PREF));
    strncat(name, (const char*) &next_read, 1);

    res = read_object_if_exists(
        name, strlen(name),
        buffer, buffer_size
    );

    return res;
}


TEE_Result queue_add(queue* ctx, const char* buffer, size_t buffer_size) {
    if (queue_full(ctx))
        return TEE_ERROR_OUT_OF_MEMORY;

    TEE_Result res;

    char name[16];
    TEE_MemFill(name, 0, sizeof(name));
    uint8_t next_write = ctx->next_write;
    strncat(name, REMOTE_ATTESTATION_QUEUE_SECSTORE_PREF, strlen(REMOTE_ATTESTATION_QUEUE_SECSTORE_PREF));
    strncat(name, (const char*) &next_write, 1);

    res = write_object(
        name, strlen(name), 
        buffer, buffer_size
    );

    if (res != TEE_SUCCESS)
        return res;

    uint8_t value = (ctx->next_write + 1) % REMOTE_ATTESTATION_QUEUE_MAX_SIZE;
    res = write_object(
        REMOTE_ATTESTATION_QUEUE_SECSTORE_NW, strlen(REMOTE_ATTESTATION_QUEUE_SECSTORE_NW),
        (char*) &value, 1
    );

    if (res != TEE_SUCCESS)
        return res;

    ctx->next_write = value;

    return TEE_SUCCESS;
}
