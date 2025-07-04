#ifndef USER_TA_HEADER_DEFINES_H
#define USER_TA_HEADER_DEFINES_H


#include <remote_attestation.h>

#define TA_UUID TA_REMOTE_ATTESTATION_UUID

#define TA_FLAGS TA_FLAG_EXEC_DDR

#define TA_STACK_SIZE (32 * 1024)
#define TA_DATA_SIZE (64 * 1024)

#define TA_VERSION "0.1"

#define TA_DESCRIPTION "A TA for Remote Attestation"


#endif /* USER_TA_HEADER_DEFINES_H */
