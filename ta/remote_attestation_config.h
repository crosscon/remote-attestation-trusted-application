#ifndef TA_REMOTE_ATTESTATION_CONIFG_H
#define TA_REMOTE_ATTESTATION_CONIFG_H

#define REMOTE_ATTESTATION_SERVER_HOST "0.0.0.0"
#define REMOTE_ATTESTATION_SERVER_PORT 5432

extern const char* REMOTE_ATTESTATION_SERVER_SSL_CERT; // Must be configured in `network_handling.c` if required

#endif
