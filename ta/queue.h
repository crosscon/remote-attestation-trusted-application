#ifndef REMOTE_ATTESTATION_QUEUE_H
#define REMOTE_ATTESTATION_QUEUE_H

#include <stdint.h>

#include <tee_internal_api.h>


#define REMOTE_ATTESTATION_QUEUE_MAX_SIZE 10

#define REMOTE_ATTESTATION_QUEUE_SECSTORE_NR        "queue_next_read"
#define REMOTE_ATTESTATION_QUEUE_SECSTORE_NW        "queue_next_write"
#define REMOTE_ATTESTATION_QUEUE_SECSTORE_PREF      "queue-"


struct queue_ctx {
    uint8_t next_read;
    uint8_t next_write;
};


typedef struct queue_ctx queue;


TEE_Result queue_get_ctx(
    queue* ctx
);


uint8_t queue_has_next(
    queue* ctx
);


uint8_t queue_full(
    queue* ctx
);


uint8_t queue_size(
    queue* ctx
);


TEE_Result queue_step(
    queue* ctx
);


TEE_Result queue_peek(
    queue* ctx,
    char* buffer,
    size_t buffer_size
);


TEE_Result queue_add(
    queue* ctx,
    const char* buffer,
    size_t buffer_size
);


#endif /* REMOTE_ATTESTATION_QUEUE_H */
