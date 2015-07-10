#!/bin/sh
SSID=$2
INT=$1

if [ $# -ne 2 ]; then
        echo "Incorrect arguments"
        exit 2;
fi

MONITOR=$( airmon-ng start $INT | grep "monitor mode" | awk '{print $5}' )
MON=$(echo ${MONITOR%?} | sed -e 's/grep//g')

echo "Started Monitor on: " $MON

./ssidlistener.py $MON $SSID

(airmon-ng stop $MON &>/dev/null)

exit 0;
