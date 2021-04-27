#!/bin/sh

docker run -it \
    --volume $1:/results \
    --volume $2:/src \
    zricethezav/gitleaks \
    --path=/src \
    -o /results/output.json
