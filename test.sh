#!/bin/sh

make test
./liar curl 39.156.66.10 -H 'Host: baidu.com'
