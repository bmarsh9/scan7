# install base
#FROM ubuntu
FROM python:3.6-slim-buster

# update the operating system:
RUN apt-get update \
 && apt-get install -y bzip2 xz-utils zlib1g libxml2-dev libxslt1-dev libgomp1 python3-pip libpq-dev nano net-tools sudo git dos2unix\
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# copy the folder to the container:
ADD . /scan7

# Define working directory:
WORKDIR /scan7

# Install the requirements
RUN pip3 install -r /scan7/requirements.txt

# expose tcp port 5000
#EXPOSE 5000

# default command: run the web server
CMD ["/bin/bash","run.sh"]
