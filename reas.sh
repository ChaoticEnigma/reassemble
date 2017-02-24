#!/bin/bash

arm-none-eabi-as -mcpu=cortex-m3 -mthumb --no-pad-sections out.s -o out.o
arm-none-eabi-ld -T ../reassemble/vma.ld -o out.elf out.o
arm-none-eabi-objcopy out.elf -O binary out.bin

