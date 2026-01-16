#
# Copyright 2025-2026 IBM
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

# 10.1-1767602397 (Has OpenSSL 3.5)
ARG currentOS=registry.access.redhat.com/ubi10/ubi@sha256:937cb57b9dead25a68ca3b40f40db874dcf7b97dd0b438aca32c54e26220b415

FROM ${currentOS} AS installed_openssl

RUN dnf install -y ca-certificates gcc procps make openssl-devel

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




