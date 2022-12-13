#!/bin/bash
set +e
# TODO : clean up
#packages=$1
#IFS=' '
##apt-get install -y --force-yes --no-install-recommends "$packages" >&2
#read -ra pack <<<"$1"

for val in "$@";
do
  echo "$val" >&2
  apt-get install -y --force-yes --no-install-recommends "$val" >&1
done

