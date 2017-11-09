FROM centos:7

MAINTAINER Elvin Tan <elvin@elvin.net>

ADD v2.0.24-64k.tar.gz /tmp
RUN yum -y install make openssl openssl-devel gnutls-devel gnutls gcc gcc-c++ perl
RUN useradd -u 10000 -d /opt/inspircd/ inspircd && \
    cd /tmp && \
    ln -sf inspircd-* inspircd && \
    cd /tmp/inspircd && \
    ./configure --disable-interactive --prefix=/opt/inspircd/ --uid 10000 --enable-openssl --enable-gnutls && \
    make && make install && \
    rm -rf "/tmp/inspircd/*"

VOLUME ["/opt/inspircd/conf"]
COPY env.sh /
COPY inspircd.conf.example /opt/inspircd
EXPOSE 6667 7000

ENTRYPOINT ["/env.sh"]
CMD ["inspircd"]

#docker run --name "irc" -d -p 6667:6667 -v /opt/irc:/opt/inspircd/conf visago/inspircd:latest
