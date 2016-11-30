#!/bin/bash
ulimit -n 4096
cd /opt/inspircd
if [ -f "/opt/inspircd/conf/inspircd.conf" ]; then
  echo "*** Using user-suppplied configuration"
else
  echo "*** Copying a default configuration file"
  cp -f /opt/inspircd/inspircd.conf.default /opt/inspircd/conf/inspircd.conf
fi
exec su - inspircd -c "/opt/inspircd/bin/inspircd --nofork"
