#!/bin/bash
#


function code_quality_error {
    echo "${1}"
}

BASE=${PWD}

echo -n "Code quality: "
cd ${BASE}/cli
PYLINTOUT=$(find . -type f -name '*.py' | grep -vi __init__ | xargs pylint)
SCORE=$(echo ${PYLINTOUT} | grep -Po '(?<=rated at ).*?(?=/10)')
echo ${SCORE}
if [[ $(bc <<< "${SCORE} > 9") == 0 ]]; then
    code_quality_error "${PYLINTOUT}"
fi
