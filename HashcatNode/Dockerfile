FROM dizcza/docker-hashcat:latest

RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip 

WORKDIR /hashcatnode/

EXPOSE 9999

# Python requirements
ADD requirements.txt /hashcatnode/
RUN pip3 install -r ./requirements.txt

COPY . .

# What to run to build image
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
