# DEbian Cve REproducer Tool (DECRET)

This tool reproduces a vulnerable Debian environment for a given CVE number.  


## License 

Copyright (c) 2023 Orange  
This code is released under the terms of the BSD 3-Clause license. See the `license.txt` file for more information.


## Requirements

- Python3
- Docker (see the [official documentation](https://docs.docker.com/engine/install/))
- Firefox


## Build

On Debian stable, a simple way to install DECRET is to first run the
following commands as `root`:

```shell
# apt install python3 python-is-python3 python3-venv
# apt install docker.io
# apt install firefox-esr
```

Then, you can download DECRET and its dependencies in a virtual
environment (using the `venv` module):

```shell
$ git clone https://github.com/Orange-OpenSource/decret.git
$ cd decret
$ python3 -m venv venv
$ source venv/bin/activate
$ pip install -r requirements-minimal.txt
```

You can use `requirements.txt` if you want to run the tests which are
run in the Continuous Integration pipeline.


## Example

You can find examples in the `examples` directory.


## Working principle

![](./img/reproduction_implementation.png)
