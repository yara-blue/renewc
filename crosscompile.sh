#!/usr/bin/env bash

cd setup_crosscompile
cargo r
cd ..
cargo b --target aarch64-unknown-linux-musl --release
