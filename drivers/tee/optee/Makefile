# SPDX-License-Identifier: GPL-2.0
obj-$(CONFIG_OPTEE) += optee.o
optee-objs += core.o
optee-objs += call.o
optee-objs += rpc.o
optee-objs += supp.o
optee-objs += device.o

optee-smc-abi-y = smc_abi.o
optee-ffa-abi-$(CONFIG_ARM_FFA_TRANSPORT) = ffa_abi.o
optee-objs += $(optee-smc-abi-y) $(optee-ffa-abi-y)

# for tracing framework to find optee_trace.h
CFLAGS_smc_abi.o := -I$(src)
