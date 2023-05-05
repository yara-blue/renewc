#!/usr/bin/env bash

set -e

# optionally takes an architecture as an argument
# then it will crosscompile. Only some cargo 
# tier 1 and tier 2 linux targets are supported

if [ $# -gt 0 ]; then
	rustup target add $1

	cd setup_crosscompile
	# pass target for which we want to set up crosscompiler
	cargo r -- $1 
	cd ../main
	cargo b --target $1 --release
else
	cd main
	cargo b --release
fi 

