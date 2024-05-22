FROM hub.opensciencegrid.org/opensciencegrid/hosted-ce:23-testing
ARG branch=master

RUN \
 cd /usr/local/src && \
 git clone -b "${branch}" https://github.com/matyasselmeci/hermitcrab

COPY image-init.d/* /etc/osg/image-init.d/

ENV CLUSTER_CONDOR_OS=AlmaLinux8
ENV CLUSTER_CONDOR_SERIES=23.x
