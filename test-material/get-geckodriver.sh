#!/bin/sh

#Software Name : decret (DEbian Cve REproducer Tool)
#Version : 0.1
#SPDX-FileCopyrightText : Copyright (c) 2023 Orange
#SPDX-License-Identifier : BSD-3-Clause
#
#This software is distributed under the BSD 3-Clause "New" or "Revised" License,
#the text of which is available at https://opensource.org/licenses/BSD-3-Clause
#or see the "license.txt" file for more not details.
#
#Author : Clément PARSSEGNY, Olivier LEVILLAIN, Maxime BELAIR
#Software description : A tool to reproduce vulnerability affecting Debian
#It gathers details from the Debian metadata and exploits from exploit-db.com
#in order to build and run a vulnerable Docker container to test and
#illustrate security concepts.

set -e

DIRNAME="$(dirname "$0")"
cd "$DIRNAME"

echo "c33054fda83b8d3275c87472dd005a9f70372e9338c2df2665d8cfeb923e67ba  geckodriver-v0.32.0-linux64.tar.gz" > geckodriver-v0.32.0-linux64.tar.gz.sha256sum
wget https://github.com/mozilla/geckodriver/releases/download/v0.32.0/geckodriver-v0.32.0-linux64.tar.gz
sha256sum -c geckodriver-v0.32.0-linux64.tar.gz.sha256sum
tar xvzf geckodriver-v0.32.0-linux64.tar.gz
