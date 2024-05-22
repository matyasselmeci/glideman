FROM hub.opensciencegrid.org/opensciencegrid/hosted-ce:23-testing
ARG branch=devel

# DEBUG: install some decent editors
RUN --mount=type=cache,target=/var/cache/yum,sharing=locked \
 yum install -y vim-enhanced nano

RUN git config --global user.name 'root'; git config --global user.email 'root@container'

ARG branch=devel

RUN \
 cd /usr/local/src && \
 git clone -b "${branch}" https://github.com/matyasselmeci/hermitcrab

COPY image-init.d/* /etc/osg/image-init.d/
COPY supervisord.d/* /etc/supervisord.d/
COPY add-local-config-d.patch /tmp/add-local-config-d.patch
RUN patch -p1 -i /tmp/add-local-config-d.patch && rm /tmp/add-local-config-d.patch

ENV CLUSTER_CONDOR_OS=AlmaLinux8
ENV CLUSTER_CONDOR_SERIES=23.x
