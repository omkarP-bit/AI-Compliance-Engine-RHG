#!/bin/bash
/usr/local/bin/opa run --server \
  --addr=localhost:8181 \
  --bundle=./policies \
  &
exec "$@"
