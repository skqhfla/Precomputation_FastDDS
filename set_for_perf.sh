#!/bin/bash

# Usage: source ./set_for_perf.sh [MODE] [BUFFER_SIZE] [INTERVAL_TIME] [KEYSTREAM_SIZE] [TARGET_LENGTH]

if [ ${#} -ne 5 ]; then
    echo "You must set test mode: [o|f]"
    return -1
fi

MODE="${1}"
BUFFER_SIZE="${2}"
INTERVAL_TIME="${3}"
KEYSTREAM_SIZE="${4}"
TARGET_LENGTH="${5}"

TYPE_HEADER_PATH="${HOME}/ros2_humble/src/eProsima/Fast-DDS/src/cpp/security/cryptography/AESGCMGMACFAST_Types.h"
DEMO_NODE_CPP_PATH="${HOME}/ros2_humble/src/ros2/demos/demo_nodes_cpp/src/topics/talker.cpp"
SCRIPT_PATH="${HOME}/ros2_humble/run_l_100times.sh"

WAIT_TIME=`cat ${DEMO_NODE_CPP_PATH} | grep create_wall_timer | cut -d '(' -f2 | cut -d ',' -f1`

echo "### Set for performance test"
echo "- Test Mode: ${MODE}"
echo "- Buffer Size: ${BUFFER_SIZE}"
echo "- Interval Time: ${INTERVAL_TIME}"
echo "- Keystream Size: ${KEYSTREAM_SIZE}"
echo "- Target Length: ${TARGET_LENGTH}"
echo "------------------------------------"

rm -rf ${HOME}/sros2_demo
echo "Settint for SROS2 Enviroment"
if [ "${MODE}" == "f" ]; then
    cp -r ${HOME}/sros2_demo0 ${HOME}/sros2_demo
    export ROS_DOMAIN_ID=0
    sed -i -e "s/MODE=.*/MODE=\"Fast\"/g" ${SCRIPT_PATH}
elif [ "${MODE}" == "o" ]; then
    cp -r ${HOME}/sros2_demo_origin ${HOME}/sros2_demo
    export ROS_DOMAIN_ID=101
    sed -i -e "s/MODE=.*/MODE=\"Origin\"/g" ${SCRIPT_PATH}
else
    echo "You must set test mode: [o|f]"
    return -1
fi

cat ${HOME}/sros2_demo/demo_keystore/enclaves/governance.xml | grep id | tr -d ' '
env | grep ROS_DOMAIN_ID
cat ${SCRIPT_PATH} | grep MODE=
echo "Done..."
echo

echo "AESGCMGMACFAST_Types.h"
sed -i -e "s/MAX_ROUND_SIZE.*/MAX_ROUND_SIZE ${BUFFER_SIZE}/g" ${TYPE_HEADER_PATH}
sed -i -e "s/WAIT_INTERVAL.*/WAIT_INTERVAL ${INTERVAL_TIME}/g" ${TYPE_HEADER_PATH}
sed -i -e "s/KEYSTREAM_SIZE.*/KEYSTREAM_SIZE ${KEYSTREAM_SIZE}/g" ${TYPE_HEADER_PATH}
cat ${TYPE_HEADER_PATH} | grep -E "MAX_ROUND_SIZE|WAIT_INTERVAL|KEYSTREAM_SIZE"
echo "Done..."
echo ""


echo "demo_nodes_cpp"
sed -i -e "s/target_length =.*/target_length = ${TARGET_LENGTH};/g" ${DEMO_NODE_CPP_PATH}
cat ${DEMO_NODE_CPP_PATH} | grep "target_length = " | cut -d ' ' -f5- | grep "target_length"
echo "Done..."
echo

echo "run_l_100times.sh"
sed -i -e "s/BUFFER_SIZE=.*/BUFFER_SIZE=\"${BUFFER_SIZE}\"/g" ${SCRIPT_PATH}
sed -i -e "s/WAIT_TIME=.*/WAIT_TIME=\"${WAIT_TIME}\"/g" ${SCRIPT_PATH}
sed -i -e "s/WAIT_INTERVAL=.*/WAIT_INTERVAL=\"${INTERVAL_TIME}nano\"/g" ${SCRIPT_PATH}
sed -i -e "s/MESSAGE_SIZE=.*/MESSAGE_SIZE=\"${TARGET_LENGTH}\"/g" ${SCRIPT_PATH}
cat ${SCRIPT_PATH} | grep -E "BUFFER_SIZE=|WAIT_TIME=|WAIT_INTERVAL=|MESSAGE_SIZE=|MODE="
echo "Done..."
echo
