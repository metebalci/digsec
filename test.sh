#!/bin/bash

EXE=scripts/validate.py
NS=1.1.1.1

EXITCODE=0

function do_test
{
  q=$1
  rr=$2
  echo "testing positive $q $rr"
	rm -rf /tmp/digsec
	mkdir /tmp/digsec
	digsec.resolve $q $rr /tmp/digsec $NS || EXITCODE=$?
  if [ $EXITCODE -ne 0 ] 
  then
    echo "exiting with 1, query fail"
    exit 1
  fi
	digsec.authenticate $q $rr /tmp/digsec || EXITCODE=$?
  if [ $EXITCODE -ne 0 ] 
  then
    echo "exiting with 1, validate fail (expected success)"
    exit 1
  fi
  echo "test success"
}

function do_ftest
{
  q=$1
  rr=$2
  echo "testing negative $q $rr"
	rm -rf /tmp/digsec
	mkdir /tmp/digsec
	digsec.resolve $q $rr /tmp/digsec $NS || EXITCODE=$?
  if [ $EXITCODE -ne 0 ] 
  then 
    echo "exiting with 1, query fail"
    exit 1
  fi
	digsec.authenticate $q $rr /tmp/digsec || EXITCODE=$?
  if [ $EXITCODE -eq 0 ] 
  then 
    echo "exiting with 1, validate success (expected fail)"
    exit 1
  fi
  echo "test success"
}

do_test . DNSKEY
do_test com DNSKEY
do_test metebalci.com DNSKEY
do_test metebalci.com A DNSKEY

do_ftest dnssec-failed.org DNSKEY
