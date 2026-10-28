# SPDX-License-Identifier: Apache-2.0
# Keep the approved upstream server and dense CUDA libraries in a smaller runtime.
ARG LLAMA_IMAGE
FROM ${LLAMA_IMAGE}

# These optional CUDA math libraries are not used by the dense llama.cpp backend.
# Refuse an upstream dependency change instead of producing a broken runtime.
RUN set -eu; \
    ldd /app/libggml-cuda.so > /tmp/ficc-cuda-libraries; \
    if grep -E 'lib(cufft|curand|cusolver|cusparse|npp|nvjpeg)' /tmp/ficc-cuda-libraries; then exit 1; fi; \
    find /usr/local/cuda*/targets/*/lib -maxdepth 1 \
      \( -name 'libcufft*' -o -name 'libcurand*' -o -name 'libcusolver*' \
         -o -name 'libcusparse*' -o -name 'libnpp*' -o -name 'libnvjpeg*' \) -delete; \
    rm /tmp/ficc-cuda-libraries
