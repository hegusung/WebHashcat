FROM dizcza/docker-hashcat:latest

RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    git

WORKDIR /hashcatnode/

EXPOSE 9999

# Python code
ADD hashcatnode.py /hashcatnode/
ADD hashcat.py /hashcatnode/
ADD httpapi.py /hashcatnode/
ADD create_database.py /hashcatnode/
ADD settings.ini.sample /hashcatnode/

# Python requirements
ADD requirements.txt /hashcatnode/

# Directories
RUN mkdir /hashcatnode/hashes
RUN mkdir /hashcatnode/masks
RUN mkdir /hashcatnode/rules
RUN mkdir /hashcatnode/wordlists
RUN mkdir /hashcatnode/potfiles
RUN mkdir /hashcatnode/outputs

# What to run to build image
RUN pip3 install -r ./requirements.txt
RUN python3 ./create_database.py
RUN openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes -subj "/C=UK/ST=Warwickshire/L=Leamington/O=OrgName/OU=IT Department/CN=example.com"

# Prepare config file
RUN cp settings.ini.sample settings.ini
RUN sed -i 's/hashcatnodeuser/DOCKER_ENV/' settings.ini
RUN sed -i 's/hashcatnodehash/DOCKER_ENV/' settings.ini
RUN sed -i 's/\/path\/to\/hashcatnode\/hashes\/dir/\/hashcatnode\/hashes/' settings.ini
RUN sed -i 's/\/path\/to\/hashcatnode\/rule\/dir/\/hashcatnode\/rules/' settings.ini
RUN sed -i 's/\/path\/to\/hashcatnode\/wordlist\/dir/\/hashcatnode\/wordlists/' settings.ini
RUN sed -i 's/\/path\/to\/hashcatnode\/mask\/dir/\/hashcatnode\/masks/' settings.ini
RUN sed -i 's/\/usr\/bin\/hashcat/\/root\/hashcat\/hashcat/' settings.ini

# What will be executed at startup
CMD [ "python3", "./hashcatnode.py" ]
