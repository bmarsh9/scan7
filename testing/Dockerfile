FROM python:3.6-slim-buster
RUN apt-get update \
 && apt-get install -y bzip2 xz-utils zlib1g libxml2-dev libxslt1-dev libgomp1 python3-pip nano net-tools sudo \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

RUN pip3 install scancode-toolkit[full] # && pip3 install typecode-libmagic
WORKDIR /
CMD ["/bin/bash"]
