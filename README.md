# DEbian Cve REproducer Tool (DECRET)

This tool reproduces a vulnerable Debian environment for a given CVE number.  

## License 
Copyright (c) 2023 Orange  
This code is released under the terms of the BSD 3-Clause license. See the `license.txt` file for more information.

## Requirements 
- Docker (see the [official documentation](https://docs.docker.com/engine/install/))
- Firefox


## Build

- Install the requirements 
- Install the python dependencies (`pip install -r requirements.txt`)


## Example

Here is an example for the Pwnkit vulnerability :
   
`python cve_debian.py -n 2021-4034 -v bullseye -d pwnkit --selenium`


## Working principle

![](./img/reproduction_implementation.png)
