#
# Copyright 2025 IBM
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

# ubi 9.6.175486119 7/8/25
ARG currentOS=registry.access.redhat.com/ubi9/ubi@sha256:8851294389a8641bd6efcd60f615c69e54fb0e2216ec8259448b35e3d9a11b06
ARG INSTALLDIR=/opt/openssl
# OpenSSL 3.5.2 commit
ARG OpenSSL3Commit=0893a62353583343eb712adef6debdfbe597c227

# Stage 1: Build - Compile and assemble all necessary components and dependencies
FROM ${currentOS} AS build_openssl
LABEL version="3"

ARG OpenSSL3Commit
ARG INSTALLDIR
ARG KEM_ALGLIST

ENV OPENSSL3_DIR=${INSTALLDIR}

# Install required build tools and system dependencies. perl-bignum required for s390x
RUN yum install -y ca-certificates gcc autoconf automake libtool make cmake perl-FindBin perl-IPC-Cmd perl-bignum && \
    yum install -y gnupg2 procps git

#--------------------------------
# LOAD VERIFICATION KEYS
#--------------------------------
# Keyserver
ARG KEY_SERVER="keyserver.ubuntu.com"
# Load keys
# PGP KeyID Matt Caswell & Richard Levitte (see here: https://www.openssl.org/community/omc.html)
RUN OpenSSL_KeyID1=8657ABB260F056B1E5190839D9C4D26D0E604491 && \
    OpenSSL_KeyID2=7953AC1FBC3DC8B3B292393ED5E9E43F7DF9EE8C && \
    gpg2 --keyserver $KEY_SERVER --recv-keys $OpenSSL_KeyID1 && \
    gpg2 --keyserver $KEY_SERVER --recv-keys $OpenSSL_KeyID2


# Build and install OpenSSL
# NOTE: this may not be the best configured openssl 3.5 setup, it was done purely for building
# and testing the library, nothing more. It's not recommended for use as a production runtime package.
RUN mkdir /build && cd /build && git clone https://github.com/openssl/openssl.git && \
    cd openssl && \
    # git verify-commit --verbose $OpenSSL3Commit && \
    git checkout $OpenSSL3Commit && \
    openssl_libdir='lib64' && if [ "$(uname -m)" = "aarch64" ]; then openssl_libdir='lib'; fi && \
    LDFLAGS="-Wl,-rpath -Wl,${INSTALLDIR}/$openssl_libdir" ./config shared --prefix=${INSTALLDIR} && \
    make -j"$(nproc)" && make install_sw install_ssldirs;

# TODO could use minimal here I guess, just not as good for development as this is used to build and copy the output as required
FROM ${currentOS} AS installed_openssl
ARG INSTALLDIR

RUN dnf install -y ca-certificates gcc procps make
RUN mkdir ${INSTALLDIR}
COPY --from=build_openssl ${INSTALLDIR} ${INSTALLDIR}

FROM installed_openssl AS test_hashmldsa

ARG hashmldir=/opt/HashMLDSA
RUN mkdir $hashmldir
COPY hashMLDSA.c $hashmldir
COPY hashMLDSA.h $hashmldir
COPY Makefile $hashmldir
COPY test*.c $hashmldir
COPY test*.h $hashmldir
RUN echo "about to run tests" && \
    cd $hashmldir && \
    make && \
    ./test_actions && \
    ./test_validation




