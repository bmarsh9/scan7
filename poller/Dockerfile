# install base
FROM ubuntu

# update the operating system:
RUN apt-get update --fix-missing
RUN apt install -y python3-pip nano net-tools sudo libpq-dev default-jre

# copy the folder to the container:
ADD . /poller

# Define working directory:
WORKDIR /poller

# Install the requirements
RUN pip3 install -r /poller/requirements.txt

# default command: run the web server
CMD ["python3","app.py"]
