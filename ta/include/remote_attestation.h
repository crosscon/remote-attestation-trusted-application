#ifndef TA_HELLO_WORLD_H
#define TA_HELLO_WORLD_H


#define TA_REMOTE_ATTESTATION_UUID \
        { 0xde86b21f, 0xe559, 0x4771, \
                { 0x96, 0x94, 0x61, 0x0b, 0x75, 0xe6, 0xb6, 0x2a} }


#define TA_REMOTE_ATTESTATION_CMD_GET_DEVICE_ID                     0
#define TA_REMOTE_ATTESTATION_CMD_ENROLL_CERT                       1
#define TA_REMOTE_ATTESTATION_CMD_REQUEST_ATTESTATION               2
#define TA_REMOTE_ATTESTATION_CMD_REQUEST_ATTESTATION_FROM_QUEUE    3
#define TA_REMOTE_ATTESTATION_CMD_TEST_REMOTE                       4


#endif /*TA_HELLO_WORLD_H*/
