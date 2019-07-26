#!/bin/bash

# voci najnovsiemu ndk 16 to neslo skompilovat ! (android-ndk-r12b)
#ANDROID_NDK_ROOT=/home/marian/programy/android-ndk-r12b
ANDROID_NDK_ROOT=/home/marian/programy/android-ndk-r13b

ARCHS="armeabi-v7a x86"
#ARCHS="x86"

for a in $ARCHS
do
	case $a in
		armeabi-v7a) ARCH="arch-arm"; EABI="x86-4.9";;
		x86) ARCH="arch-x86"; EABI="arm-linux-androideabi-4.9";;
	esac

	export ARCH
    export EABI
	. ./setenv-android.sh
	
	cd openssl/
	./config shared no-ssl2 no-ssl3 no-comp no-hw no-engine \
		--openssldir=/usr/local/ssl/$ANDROID_API \
		--prefix=/usr/local/ssl/$ANDROID_API

	make depend
	make clean
	make all

	cd ..
	mkdir $a
	cp openssl/libcrypto.a $a
	cp openssl/libssl.a $a
done
