#!/bin/sh

rm -rf ./caddy_array.c
./generate_array.py ./caddy > ./caddy_array.c

rm -rf ./caddy_conf_array.c
./generate_array.py ./caddyconf > ./caddy_conf_array.c

rm -rf ./checkchange_array.c
./generate_array.py ./checkchange > ./checkchange_array.c

make clean
make
