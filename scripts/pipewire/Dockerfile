FROM rust:1.98.0-bookworm@sha256:82150a52ec202c1b14d7817e14516c392bb7f5cfebd88f1ed531cb37ebd39922

ARG PIPEWIRE_COMMIT=3b2cb4fb037bf6033b87d3c87ee917b2f686d309
ARG PIPEWIRE_SHA256=c8746b3c3408becb27e40cf67a5587105f057cd540769db4c345a67bf45c86df

RUN apt-get update && apt-get install -y --no-install-recommends \
    meson ninja-build pkg-config libsndfile1-dev libssl-dev libasound2-dev \
    && rm -rf /var/lib/apt/lists/*
RUN curl -fsSL "https://codeload.github.com/PipeWire/pipewire/tar.gz/${PIPEWIRE_COMMIT}" -o /tmp/pipewire.tar.gz \
    && printf '%s  /tmp/pipewire.tar.gz\n' "$PIPEWIRE_SHA256" | sha256sum --check \
    && mkdir /tmp/pipewire \
    && tar -xzf /tmp/pipewire.tar.gz -C /tmp/pipewire --strip-components=1 \
    && meson setup /tmp/pw-build /tmp/pipewire --prefix=/opt/pipewire --libdir=lib \
       --buildtype=release -Dauto_features=disabled -Dsession-managers=[] \
       -Dspa-plugins=enabled -Dsupport=enabled -Daudioconvert=enabled \
       -Daudiomixer=enabled -Draop=enabled -Dsndfile=enabled -Dpw-cat=enabled \
       -Ddbus=disabled -Dflatpak=disabled -Dexamples=disabled -Dtests=disabled \
       -Dpipewire-jack=disabled -Dpipewire-v4l2=disabled \
    && meson compile -C /tmp/pw-build -j 4 \
    && meson install -C /tmp/pw-build \
    && rm -rf /tmp/pipewire /tmp/pw-build /tmp/pipewire.tar.gz

ENV PATH="/opt/pipewire/bin:${PATH}" \
    LD_LIBRARY_PATH=/opt/pipewire/lib \
    PIPEWIRE_QUALIFICATION_VERSION=1.6.7 \
    PIPEWIRE_QUALIFICATION_COMMIT=${PIPEWIRE_COMMIT} \
    PIPEWIRE_QUALIFICATION_SHA256=${PIPEWIRE_SHA256} \
    RUSTUP_TOOLCHAIN=1.98.0 \
    CARGO_HOME=/cargo \
    CARGO_TARGET_DIR=/target
RUN rustup component add clippy rustfmt --toolchain 1.98.0
RUN useradd --create-home --uid 10001 qualification \
    && mkdir /cargo /target /evidence \
    && chown qualification:qualification /cargo /target /evidence
USER qualification
WORKDIR /repo
