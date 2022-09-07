#!/usr/bin/env bash

TARGET_CC=$(pwd)/aarch64-linux-musl-cross/bin/aarch64-linux-musl-gcc
TARGET_AR=$(pwd)/aarch64-linux-musl-cross/bin/aarch64-linux-musl-ar

TARGET_CC=$TARGET_CC cargo b --target aarch64-unknown-linux-musl --release
