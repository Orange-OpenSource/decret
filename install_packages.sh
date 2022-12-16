#!/bin/bash
set +e
for val in "$@";
do
  echo "$val" >&2
  apt-get install -y --force-yes --no-install-recommends "$val" >&1
done