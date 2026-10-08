ARG BASE_IMAGE=ghcr.io/cpeter1207/rpt-advanced-quality-debian13:latest
ARG RUFF_VERSION=0.16.8
FROM ${BASE_IMAGE}
ARG RUFF_VERSION

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
		build-essential cargo debhelper dpkg-dev pkg-config python3-pip rustc && \
	rm -rf /var/lib/apt/lists/*
RUN python3 -m pip install --break-system-packages --no-cache-dir --disable-pip-version-check \
	--no-deps "ruff==${RUFF_VERSION}" && ruff --version | grep -F "${RUFF_VERSION}"

WORKDIR /workspace
