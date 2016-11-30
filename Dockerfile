FROM centos:7

MAINTAINER Elvin Tan <elvin@elvin.net>

ADD v2.0.23.zip /tmp/

RUN yum -y install  make openssl openssl-devel gnutls-devel gnutls gcc gcc-c++ perl
RUN  useradd -u 10000 -d /opt/inspircd/ inspircd && \
    cd /tmp && \
    unzip v2.0.23.zip && \
    ln -sf inspircd-* inspircd && \
    cd /tmp/inspircd && \
    ./configure --disable-interactive --prefix=/opt/inspircd/ --uid 10000
    --enable-openssl --enable-gnutls && \
    make && make install && \
    rm -rf "/tmp/inspircd/*"

VOLUME ["/opt/inspircd/conf"]
COPY env.sh /
COPY inspircd.conf.default /opt/inspircd
EXPOSE 6667 6697

ENTRYPOINT ["/env.sh"]
CMD ["inspircd"]

#docker run -d -p 6667:6667 -v /home/myuser/config:/opt/inspircd/conf
#visago/inspircd
