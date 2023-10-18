#!/bin/bash

if [ "$1" == "stdin" ]; then
  read -r inputdata
  echo "STDIN DATA: $inputdata"
elif [ "$1" == "timeout1" ]; then
  sleep 1
  exit 1
elif [ "$1" == "timeout2" ]; then
  sleep 2
  exit 2
elif [ "$1" == "timeout10" ]; then
  sleep 10
elif [ "$1" == "bigdata" ]; then
  for i in {1..400000}
  do
    echo "ALICEWASBEGINNINGTOGETVERYTIREDOFSITTINGBYHERSISTERONTHEBANKANDO"
  done
elif [ "$1" == "envtest" ]; then
  echo "$CHRONOSASYNC"
elif [ "$1" == "noterm" ]; then
  trap -- '' SIGTERM
  while true; do
    sleep 1
  done
else
  echo "arguments missing"
fi
