global-incdirs-y += include
srcs-y += remote_attestation.c
srcs-y += command_parser.c
srcs-y += certificate_handling.c
srcs-y += network_handling.c
srcs-y += storage_handling.c
srcs-y += queue.c
srcs-y += utils.c

# To remove a certain compiler flag, add a line like this
#cflags-template_ta.c-y += -Wno-strict-prototypes
