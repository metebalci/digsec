#!/bin/bash

# This is a script used for development, not for users

lsarg=$1
cmd=$2

eval $cmd
while find . -name "$lsarg" | inotifywait -e close_write --fromfile -;
do
  eval $cmd
done
