#!/bin/bash

# -v /var/bootc:/usr/bin/bootc:ro,Z \

podman run \
--rm --privileged \
--pid=host \
-v /dev:/dev \
-v /var/lib/containers:/var/lib/containers \
-v /home/ppoudyal/RedHat/composefs-rs/target/release/cfsctl:/bin/cfsctl:ro,Z \
--security-opt label=type:unconfined_t \
--env RUST_LOG=debug \
--env RUST_BACKTRACE=1 \
localhost/bootc-update \
sleep 10000
