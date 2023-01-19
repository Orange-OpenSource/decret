ARG DEBIAN_RELEASE
FROM debian:${DEBIAN_RELEASE}

ARG DIRECTORY
COPY ${DIRECTORY}/snapshot.list /etc/apt/sources.list.d/snapshot.list

ARG DEFAULT_PACKAGE APT_FLAG
RUN apt-get -o Acquire::Check-Valid-Until=false -o Acquire::AllowInsecureRepositories=true -o Acquire::AllowDowngradeToInsecureRepositories=true update || true
RUN apt-get install -y ${APT_FLAG} --fix-missing ${DEFAULT_PACKAGE} || (printf "\nCouldn't install basic packages %s.\n" "${DEFAULT_PACKAGE}" >&2 && false)

ARG PACKAGE_NAME APT_FLAG FIXED_VERSION
RUN aptitude -y --allow-untrusted -o Aptitude::ProblemResolver::SolutionCost='100*canceled-actions,200*removals' install ${PACKAGE_NAME} || (echo "\n\n /!\\ WARNING /!\\ \n\nThe vulnerable packages could not be installed. Please provide the bin-package name with '-p' option (see -h for help).\nCheck also that you are using the right Debian version.\nFinally, you can try to add an other version, older than ${FIXED_VERSION}, by running the command : apt-cache policy package_name\nThen install the desired version with :  aptitude install package_name=version\n\n /!\\ WARNING /!\\ \n\n" >&2)
RUN adduser --gecos "To To, 42, 4242, 4242" --disabled-password toto
