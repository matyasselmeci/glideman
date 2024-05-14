if pushd /usr/local/src/hermitcrab/ministarter; then
    ./compose.py \
        --os="${CLUSTER_CONDOR_OS}" \
        --series="${CLUSTER_CONDOR_SERIES}" \
        --pilotfile=/var/lib/condor-ce/pilot.pyz
    popd
fi
