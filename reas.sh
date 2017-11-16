#!/bin/bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

if [ -z "$1" ]; then
    exit
fi

rm -f /tmp/out.o "$1.elf"

arm-none-eabi-as -mcpu=cortex-m3 -mthumb --no-pad-sections "$1" -o /tmp/out.o
arm-none-eabi-ld -T "$DIR/vma.ld" -o "$1.elf" /tmp/out.o
arm-none-eabi-objcopy "$1.elf" -O binary "$1.bin"

if [ ! -z "$2" ]; then
    md5sum "$1.bin" "$2"
fi
