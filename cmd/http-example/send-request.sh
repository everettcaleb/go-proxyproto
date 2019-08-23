#!/bin/bash
# Note: for this to work you need curl/7.60 or later.
# On macOS, you must do `brew install curl` and then add:
# export PATH="/usr/local/opt/curl/bin:$PATH" to your bash/z profile
curl --haproxy-protocol http://localhost:8080/