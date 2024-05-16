FROM hub.opensciencegrid.org/opensciencegrid/hosted-ce:23-testing

RUN \
 cd /usr/local/src && \
 git clone https://github.com/matyasselmeci/hermitcrab

RUN \
 mkdir -p /etc/condor-ce/gltokens && \
 for n in $(seq -w 1 20); do \
    uu=osg${n}; \
    if [ -d "/home/$uu" ]; then \
        install -o "$uu" -g "$uu" -m 0700 -d /etc/condor-ce/gltokens/"$uu"; \
    fi; \
 done

COPY image-init.d/* /etc/osg/image-init.d/

ENV CLUSTER_CONDOR_OS=AlmaLinux8
ENV CLUSTER_CONDOR_SERIES=23.x
