# syntax=docker/dockerfile:1.7
#
# Commit-image Dockerfile for wargus (SMALL form) — builds ON TOP of the org C/C++ base image
# (ghcr.io/savantenvs/base), which already provides clang/llvm + libFuzzer/afl++ + the identities
# + the build-contract ENV. wargus's two Mayhem targets (Parse, pudconvert) need only zlib
# (zlib1g-dev, already in the base) — no extra apt packages required.
FROM ghcr.io/savantenvs/base:20260621

ARG COMMIT
ARG REPO_URL
# SOURCE_DATE_EPOCH stays an ARG (available to build.sh); NOT baked as ENV — an empty value
# breaks clang ("must be a non-negative decimal integer"). build.sh unsets it when empty.
ARG SOURCE_DATE_EPOCH

# Sanitizer override: base exports SANITIZER_FLAGS (ASan+UBSan, halting) as the default.
# Undefaulted ARG (no '=') lets the base ENV flow through when not passed; an explicit
# --build-arg SANITIZER_FLAGS="..." overrides it.
ARG SANITIZER_FLAGS
# Coverage (optional, off by default; never used for fuzzing or grading) — mayhem/build.sh adds it to
# every object and binary it builds (there is no separate test build: test.sh runs the graded
# binaries); empty = no effect.
ARG COVERAGE_FLAGS=
# Build parallelism (optional); build.sh falls back to nproc when unset.
ARG MAYHEM_JOBS=

# Source enters from the build CONTEXT (the CI checkout): the FULL repo (incl. .git history) is
# copied to /mayhem as `mayhem`; build.sh builds in place.
USER mayhem
WORKDIR /mayhem
COPY --chown=2000:2000 . /mayhem

RUN bash mayhem/build.sh

# Run wargus's functional test suite (the behavioral pud-conversion oracle) at build time. A
# failing suite fails the image build.
RUN if [ -f mayhem/test.sh ]; then bash mayhem/test.sh; else echo "no mayhem/test.sh — repo ships no functional tests"; fi

LABEL org.opencontainers.image.source="${REPO_URL}" \
      org.opencontainers.image.revision="${COMMIT}" \
      rlenv.tier="commit" \
      rlenv.source_date_epoch="${SOURCE_DATE_EPOCH}" \
      rlenv.user="mayhem"

USER mayhem
WORKDIR /mayhem
