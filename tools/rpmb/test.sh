#!/bin/sh -e
# SPDX-License-Identifier: GPL-2.0+
echo "get info"
./rpmb -v get-info /dev/rpmb0
echo "program key"
./rpmb -v program-key /dev/rpmb0 key
echo "get write counter"
./rpmb -v write-counter /dev/rpmb0
echo "get write counter (and verify)"
./rpmb -v write-counter /dev/rpmb0 key
echo "generating data"
dd if=/dev/urandom of=data.in count=4 bs=256
echo "write data"
./rpmb -v write-blocks /dev/rpmb0 0 4 data.in key
echo "read data back"
rm -f data.out
./rpmb -v read-blocks /dev/rpmb0 0 4 data.out
cmp data.in data.out
echo "read data back with key check"
truncate -s 0 data.out
./rpmb -v read-blocks /dev/rpmb0 0 4 data.out key
cmp data.in data.out
