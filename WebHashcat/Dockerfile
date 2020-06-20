FROM ubuntu:focal

RUN apt-get update && \
    apt-get install -y python3 python3-pip libmysqlclient-dev

WORKDIR /

RUN apt-get update && \
    apt-get install -y wget make clinfo build-essential git libcurl4-openssl-dev libssl-dev zlib1g-dev libcurl4-openssl-dev libssl-dev

ENV HASHCAT_VERSION        master
RUN git clone https://github.com/hashcat/hashcat.git && cd hashcat && git checkout ${HASHCAT_VERSION} && make install -j4

WORKDIR /webhashcat

# Installing requirements
RUN pip3 install --upgrade pip
COPY ./requirements.txt /webhashcat/requirements.txt
RUN pip3 install -r requirements.txt

# Copying files
COPY ./API /webhashcat/API
COPY ./Auth /webhashcat/Auth
COPY ./Hashcat /webhashcat/Hashcat
COPY ./Nodes /webhashcat/Nodes
COPY ./Utils /webhashcat/Utils
COPY ./WebHashcat /webhashcat/WebHashcat
RUN rm /webhashcat/WebHashcat/settings.py
COPY ./static /webhashcat/static
COPY ./manage.py /webhashcat/manage.py
COPY ./settings.ini.docker /webhashcat/settings.ini.docker
COPY ./entrypoint.sh /webhashcat/entrypoint.sh
RUN chmod +x /webhashcat/entrypoint.sh

# Preparing empty directories
RUN mkdir /webhashcat/Files
RUN mkdir /webhashcat/Files/Crackedfiles
RUN mkdir /webhashcat/Files/Hashfiles
RUN mkdir /webhashcat/Files/Maskfiles
RUN mkdir /webhashcat/Files/Rulefiles
RUN mkdir /webhashcat/Files/Wordlistfiles
RUN mkdir /webhashcat/Files/tmp
RUN chmod 777 /webhashcat/Files/tmp

# Preparing configuration
RUN cp /webhashcat/WebHashcat/settings.py.docker /webhashcat/WebHashcat/settings.py
RUN cp /webhashcat/settings.ini.docker /webhashcat/settings.ini

# Entrypoint
ENTRYPOINT ["/webhashcat/entrypoint.sh"]

