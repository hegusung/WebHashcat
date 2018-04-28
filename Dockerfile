FROM python:3.6.5

ARG BUILD_DATE
ARG MAKEFLAGS=-j12
ARG VCS_REF

LABEL org.label-schema.build-date=$BUILD_DATE \
      org.label-schema.name="WebHashcat" \
      org.label-schema.description="Hashcat web interface" \
      org.label-schema.vcs-ref=$VCS_REF \
      org.label-schema.vcs-url="https://github.com/hegusung/WebHashcat" \
      org.label-schema.schema-version="1.0"

ENV HASHCAT_COMMIT=f6cfcbb \
    RUNTIME_DEPS="apache2 apache2-dev" \
    WEBHASHCAT_COMMIT=79d737e \
    WHC_DB_HOST=localhost \
    WHC_DB_NAME=webhashcat \
    WHC_DB_PASSWORD=password \
    WHC_DB_PORT=3306 \
    WHC_DB_USER=webhashcat \
    WHC_DEBUG=false \
    WHC_SECRET_KEY=supersecret

# hashcat
RUN apt-get update \
    && apt-get install -y ${RUNTIME_DEPS} \
    && cd /root \
    && git clone -n https://github.com/hashcat/hashcat \
    && cd hashcat \
    && git checkout ${HASHCAT_COMMIT} \
    && git submodule update --init \
    && make SHARED=1 \
    && make install \
    && rm -rf /root \
    && mkdir /root

# webhashcat
COPY . /root
RUN mv /root/WebHashcat /WebHashcat \
    && mkdir /etc/supervisor.d \
    && mv /root/supervisor/* /etc/supervisor.d/ \
    && cd /WebHashcat \
    && mv WebHashcat/settings.py.docker WebHashcat/settings.py \
    && pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir mod_wsgi \
    && ./manage.py collectstatic --noinput \
    && useradd -u 1000 -r hashcat \
    && chown -R hashcat:hashcat /WebHashcat \
    && rm -rf /root \
    && mkdir /root

EXPOSE 8000

USER hashcat
ENTRYPOINT ["/WebHashcat/manage.py", "runmodwsgi"]
