#!/bin/sh
#/home/naushada/build_root/Pi3B/buildroot-2017.02.1/output/host/usr/bin
export LD_LIBRARY_PATH="/usr/local/openssl-1.1.0e/lib"
#valgrind --leak-check=full \
#         --show-leak-kinds=all \
#         --track-origins=yes \
#         --verbose \
#         --log-file=valgrind-out.txt \
../src/Trench ../src/.acc_db
