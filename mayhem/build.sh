#!/usr/bin/env bash
#
# mayhem/build.sh — build wargus's two Mayhem targets.
#
# wargus (Wargus/wargus) is a Warcraft II data-file toolkit for the Stratagus engine. The full
# CMake project (wargus/wartool/warextract GUI+CLI tools) needs SDL2/libpng/Lua/the Stratagus
# headers to link, but BOTH fuzz targets live entirely in two small, dependency-light files that
# the retired mayhemheroes integration already isolated:
#   - pud.cpp/pud.h   PudData::Parse() — deserializes the ".pud" Warcraft II map container
#                     format (TYPE/DESC/OWNR/DIM/MTXM/UNIT/... chunks) into a PudData object,
#                     then PudToStratagus() re-emits it as Stratagus .smp/.sms Lua script files
#                     (gzip-compressed via zlib). This is the actual parser under fuzz.
#   - pudconvert.cpp  the `pudconvert inputfile [outputdir]` CLI — reads a file, calls
#                     PudToStratagus() directly. No CMake/Stratagus/SDL2 needed; only zlib
#                     (already in the base image as zlib1g-dev).
# So both targets are built directly with $CXX, exactly like the old integration's Dockerfile
# did (`g++ pudconvert.cpp pud.cpp -lz -o pudconvert`) -- just now instrumented + DWARF<4 per the
# base-image build contract, plus a standalone reproducer for the libFuzzer target.
#
# Targets:
#   Parse       libFuzzer harness (mayhem/fuzz_Parse.cpp) over PudData::Parse -- in-process,
#               needs both /mayhem/fuzz_Parse (Mayhem target) and /mayhem/fuzz_Parse-standalone
#               ($STANDALONE_FUZZ_MAIN run-once reproducer).
#   pudconvert  raw file-input CLI target -- /mayhem/pudconvert itself IS the reproducer (a plain
#               `pudconvert <file>` process, no libFuzzer runtime involved), so no separate
#               -standalone binary is needed for it (same shape as the verovio/dasm raw targets).
#
# ONE BUILD OF THE PROJECT CODE, AND test.sh RUNS THE GRADED BINARIES (issue #1460 A, follow-up to
# QA #1131). pud.cpp -- the only project file any target runs -- is compiled exactly ONCE, into one
# object, with the graded flags ($SANITIZER_FLAGS $DEBUG_FLAGS plus the compile-time half of
# $LIB_FUZZING_ENGINE, -fsanitize=fuzzer-no-link, which gives a byte-identical object to compiling it
# with -fsanitize=fuzzer). That object is linked into fuzz_Parse, fuzz_Parse-standalone and
# pudconvert. There is no separate test build: mayhem/test.sh runs /mayhem/pudconvert itself, and
# checks PudData::Parse on the `parse` target's path by running /mayhem/fuzz_Parse itself (the
# harness's dump mode, see mayhem/fuzz_Parse.cpp). The old oracle binary (upstream pudconvert.cpp +
# pud.cpp at -O2, no sanitizers) differed from the graded -O0 sanitized build, so a pud.cpp patch
# gated on a flag difference (`#ifndef __OPTIMIZE__`, `__has_feature(address_sanitizer)`,
# `coverage_sanitizer`, `__NO_INLINE__` ...) could neuter the parser only where the PoVs replay while
# test.sh stayed 18/18 (F = 1.0). A separately compiled test TU would not be enough either: pud.h is
# included into every TU that calls Parse, so a pud.h/pud.cpp patch can also key on that TU's context
# (a header guard such as FuzzedDataProvider.h's, __BASE_FILE__) or on symbols only the harness links
# (a weak reference to a FuzzedDataProvider method). Because test.sh runs the very binaries the
# targets fuzz, none of these compile-time or link-time properties differs between the code it
# checks and the graded code. (The same shape as fast_rsync, #1122, whose oracle is built by the same
# `cargo fuzz build` as its target.) A patch can still key on what differs at run time (the dump
# mode's environment variable, argv, the input bytes); see mayhem/test.sh.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' (empty) — it must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# Build knobs from the ENV, overridable (SANITIZER_FLAGS uses `=` so an explicit EMPTY value
# --build-arg SANITIZER_FLAGS= is honored -> no-sanitizer build with natural crashes).
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

# The flags every project/harness object is compiled with. $COVERAGE_FLAGS is empty by default (no
# effect); a source-coverage measurement build (--build-arg COVERAGE_FLAGS="-fprofile-instr-generate
# -fcoverage-mapping", never used for fuzzing or grading) instruments every object and binary here,
# since there is no separate test build: the binaries test.sh runs are the graded ones.
PROJECT_FLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link $COVERAGE_FLAGS"
LINK_FLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS $COVERAGE_FLAGS"
# Objects go to a private scratch dir (never into the source tree), removed on exit; every run
# rebuilds from source, so build.sh stays idempotent and clean-tree-safe.
OBJ="$(mktemp -d "${TMPDIR:-/tmp}/wargus-build.XXXXXX")"
trap 'rm -rf "$OBJ"' EXIT

# 0) Compile once: the parser (pud.cpp), the Parse harness, pudconvert's leak-free main(), and the
#    standalone driver. The standalone driver is compiled as a C object
#    so its LLVMFuzzerTestOneInput reference keeps C linkage (clang++ would mangle it and miss the
#    harness's extern "C" definition).
$CXX $PROJECT_FLAGS -std=c++17 -I"$SRC" -c "$SRC/pud.cpp" -o "$OBJ/pud.o"
$CXX $PROJECT_FLAGS -std=c++17 -I"$SRC" -c "$SRC/mayhem/fuzz_Parse.cpp" -o "$OBJ/fuzz_Parse.o"
$CXX $PROJECT_FLAGS -std=c++17 -I"$SRC" -c "$SRC/mayhem/pudconvert_wrapper_main.cpp" \
     -o "$OBJ/pudconvert_main.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$OBJ/standalone_main.o"

# 1) Parse target -- harness + the shared pud.o, linked with $LIB_FUZZING_ENGINE. pud.o carries the
#    SanitizerCoverage instrumentation (fuzzer-no-link), so libFuzzer is guided by the parser itself,
#    not just the harness TU. This binary is ALSO the one mayhem/test.sh runs (in the harness's dump
#    mode) to check PudData::Parse on this target's path.
$CXX $LINK_FLAGS $LIB_FUZZING_ENGINE "$OBJ/fuzz_Parse.o" "$OBJ/pud.o" -lz -o /mayhem/fuzz_Parse

# 1b) Standalone (non-fuzzer) reproducer for Parse: the same two objects against
#     $STANDALONE_FUZZ_MAIN instead of the fuzzing engine (-fsanitize=fuzzer-no-link at link time
#     resolves the coverage callbacks without pulling in libFuzzer's main()).
$CXX $LINK_FLAGS -fsanitize=fuzzer-no-link "$OBJ/fuzz_Parse.o" "$OBJ/pud.o" \
     "$OBJ/standalone_main.o" -lz -o /mayhem/fuzz_Parse-standalone

# 2) pudconvert target -- the CLI, from the same shared pud.o (compiled with fuzzer-no-link, the
#    fleet's raw-CLI convention, so the raw target is coverage-instrumented too). This binary is
#    ALSO the one mayhem/test.sh runs. Content-dispatches on the "TYPE"/"WAR2 MAP" magic inside
#    PudData::Parse (verified locally: parsing succeeds identically whether the input file is named
#    *.pud or not -- the ".pud" suffix strip in main() only affects the OUTPUT basename, never
#    whether the file gets parsed), so bare `@@` in the Mayhemfile is sufficient; see
#    mayhem/Mayhemfile_pudconvert for the outdir note.
#    LEAK-FREE main(): upstream's pudconvert.cpp main() strdup()s the input path and then
#    overwrites the pointer with basename()/dirname()'s return value, leaking on EVERY successful
#    conversion. Under ASan+LSan that is a nonzero exit for every input, which Mayhem reads as
#    "the target crashes on every test case" (run #2) and refuses to start. Suppressing LSan is
#    hard-failed by verify-repo.sh (Mayhem owns the ASAN option set), and editing pudconvert.cpp
#    would break additivity -- so the binary links mayhem/pudconvert_wrapper_main.cpp INSTEAD of
#    pudconvert.cpp (which holds only main() and usage()). The fuzzed surface is unchanged:
#    PudToStratagus() in pud.cpp, called with the same buffer/length/name/outdir.
$CXX $LINK_FLAGS -fsanitize=fuzzer-no-link "$OBJ/pudconvert_main.o" "$OBJ/pud.o" -lz \
     -o /mayhem/pudconvert
