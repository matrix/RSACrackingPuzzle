#!/usr/bin/env bash

WGET="$(which wget 2>/dev/null)"
UNZIP="$(which unzip 2>/dev/null)"

err=0
if [ ! -f "${WGET}" ]; then
	echo "! missing 'wget' binary ..."
	((err++))
fi

if [ ! -f "${UNZIP}" ]; then
	echo "! missing 'unzip' binary ..."
	((err++))
fi

if [ ${err} -gt 0 ]; then
	exit 1
fi

${WGET} -c http://www.loyalty.org/~schoen/rsa/challenge.zip
if [ -f challenge.zip ]; then
	rm -rf challenge
	${UNZIP} challenge.zip
fi
