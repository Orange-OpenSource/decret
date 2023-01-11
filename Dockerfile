ARG DEBIAN_VERSION
FROM debian:${DEBIAN_VERSION}

ARG DIRECTORY
COPY ${DIRECTORY}/snapshot.list /etc/apt/sources.list.d/snapshot.list

ARG DEFAULT_PACKAGE="strace nano"  APT_FLAG
RUN apt-get -o Acquire::Check-Valid-Until=false -o Acquire::AllowInsecureRepositories=true -o Acquire::AllowDowngradeToInsecureRepositories=true update && apt-get install -y ${APT_FLAG} --fix-missing ${DEFAULT_PACKAGE} || printf "\nCouldn't install basic packages %s.\n" "${DEFAULT_PACKAGE}" >&2

COPY install_packages.sh .
ARG PACKAGE_NAME APT_FLAG
RUN chmod +x ./install_packages.sh && apt-get install -t unstable -y --no-install-recommends ${APT_FLAG} ${PACKAGE_NAME} || (echo "\n\n /!\\ WARNING /!\\ \n\nThe vulnerable package could not be installed. Please provide the bin-package name with '-p' option (see -h for help). Check also that you are using the right Debian version.\n\n /!\\ WARNING /!\\ \n\n" >&2 && false)
RUN adduser --gecos "To To, 42, 4242, 4242" --disabled-password toto
