#!/bin/sh

set -e

DIRNAME="$(dirname "$0")"
cd "$DIRNAME"

echo "c33054fda83b8d3275c87472dd005a9f70372e9338c2df2665d8cfeb923e67ba  geckodriver-v0.32.0-linux64.tar.gz" > geckodriver-v0.32.0-linux64.tar.gz.sha256sum
wget https://github.com/mozilla/geckodriver/releases/download/v0.32.0/geckodriver-v0.32.0-linux64.tar.gz
sha256sum -c geckodriver-v0.32.0-linux64.tar.gz.sha256sum
tar xvzf geckodriver-v0.32.0-linux64.tar.gz
