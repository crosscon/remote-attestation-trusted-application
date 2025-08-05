# Remote Attestation

This Trusted Application provides a basic Remote Attestation service on the CROSSCON Hypervisor.

## Configuration

In general, only three options must be configured:
- remote server host name: change in `ta/remote_attestation_config.h` as necessary
- remote server port: similar to host name
- remote server SSL cert: change in `ta/network_handling.c` (located at the top)


## Build & Installation

Building this TA works similar to building other TAs for OPTEE-OS on CROSSCON and depends on the exact build system used. [These instructions](https://github.com/crosscon/CROSSCON-Hypervisor-and-TEE-Isolation-Demos/) can generally be used as guidance for getting a running system (in particular, step 6 shows how to compile a TA).
Instead of the default CROSSCON-modified version of OP-TEE OS, [this GitHub repo](https://github.com/crosscon/remote-attestation-optee-os/tree/separate-config) must be used as a basis, since attesting another VM requires an extension to the OP-TEE OS core.
This modification requires no modifications for the way OP-TEE OS is built.

After compilation, the signed TA application `.ta` file must be stored on the Linux file system which invokes the TA execution at `/usr/lib/optee_armtz`. This again depends on the build system used. In the CROSSCON demo repository (which uses buildroot), the developers move the TA and the host application using overlays (see there for further details).


## Usage

An example host application for how to call the TA can be found in the `host` directory for guidance. The TA command IDs are stored in the TA's header file which is located in `ta/include`.

The following commands are available:

### GET_DEVICE_ID
- description: 
- params:
    - VALUE_OUTPUT (where retrieved ID will be returned)
    - NONE/NONE/NONE
- return value: TEE_SUCCESS on ID retrieval (ID found in first parameter)

### ENROLL_CERT
- description: 
- params: NONE/NONE/NONE/NONE
- return value: TEE_SUCCESS on successful enrollment, TEE_ERROR_EXTERNAL_CANCEL on server abort (e.g. already enrolled)

### REQUEST_ATTESTATION
- description: Takes a measurement and tries to send it to the server for attestation; if remote is unreachable, puts it in the queue
- params:
    - VALUE_INPUT (index of VM to be attested)
    - MEMREF_INPUT (memory pattern from where the attestation will start)
    - VALUE_INPUT (size of the memory region to be attested)
    - NONE
- return value:

### REQUEST_ATTESTATION_FROM_QUEUE
- description: Long-running task which waits for a job to appear in the queue and a successful attestation attempt to be made (i.e. the server to be reachable)
- params: NONE/NONE/NONE/NONE
- return value: TEE_SUCCESS on successful attestation, TEE_ERROR_EXTERNAL_CANCEL on failed attestation

### TEST_REMOTE
- description: Used to test secure mTLS connection to the remote side
- params: NONE/NONE/NONE/NONE
- return value: TEE_SUCCESS on successful connection
