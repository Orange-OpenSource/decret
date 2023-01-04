#!/bin/bash
set +e
for val in "$@";
do
  echo "$val" >&2
  apt-get install -t unstable -y --allow-unauthenticated --allow-downgrades --no-install-recommends "$val" >&1 # -t to specify the repo unstable
done