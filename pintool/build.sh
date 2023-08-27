#!/bin/bash

# TODO: REMOVE?

pin_path=../pin_linux
cd $(dirname $0)

mkdir obj-ia32
mkdir obj-ia32/utils

make TARGET=ia32 PIN_ROOT=$pin_path
# make DEBUG=1 TARGET=ia32 PIN_ROOT=$pin_path