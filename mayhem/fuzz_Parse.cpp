// mayhem/fuzz_Parse.cpp — libFuzzer harness over PudData::Parse (pud.cpp), the .pud map
// deserializer at the heart of both wargus targets (pudconvert's CLI wraps the same call).
// Ported from the retired mayhemheroes/wargus integration (mayhem/fuzz_Parse.cpp) — same harness
// shape, now built by mayhem/build.sh against the base image's sanitizer/DWARF contract instead of
// a bespoke Dockerfile. The one addition is the dump mode below, which only runs when test.sh sets
// $WARGUS_PARSE_ORACLE_OUT. With the variable unset (fuzzing, PoV replay) the harness does what it
// always did: copy the first 100 bytes of the input into a 100-byte buffer and parse that buffer.
//
// DUMP MODE (issue #1460 A). mayhem/test.sh runs this binary, /mayhem/fuzz_Parse, as
//     WARGUS_PARSE_ORACLE_OUT=<file.gz> /mayhem/fuzz_Parse <input>
// libFuzzer executes that one input and exits. If Parse accepts the input, the harness writes what
// it decoded to <file.gz> with PudData::WriteSMP and WriteSMS (the writers PudToStratagus uses), as
// one gzip stream; if Parse rejects it, the harness writes no file and prints "PARSE-FAILED".
// test.sh requires that output to match what /mayhem/pudconvert wrote for the same fixture. The
// point is that test.sh checks Parse in the graded binary itself: the same objects, compiled with
// the same flags, with the same headers in scope and the same symbols linked. So a pud.cpp/pud.h
// patch cannot key on anything that differs between the build test.sh checks and the build the
// `parse` PoVs replay against (a compile flag, a header guard such as FuzzedDataProvider.h's,
// __BASE_FILE__, a weak reference to a harness-only symbol). It can still key on something that
// differs at run time, such as this variable or the input itself.
//   Inputs of at most 100 bytes (test.sh's map100.pud, named100.pud and its garbage input) take
// exactly the fuzzing path above. The fuzzing path would parse only the first 100 bytes of a longer
// input, so dump mode parses a longer input (test.sh's farscape2006.pud and twokeeps.pud) whole,
// as pudconvert does.
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <climits>

#include <fuzzer/FuzzedDataProvider.h>

#include "pud.h"

// The dump file test.sh asked for, or NULL (always NULL under fuzzing and PoV replay).
static const char *DumpPath()
{
    static const char *const path = getenv("WARGUS_PARSE_ORACLE_OUT");
    return path;
}

static void Dump(const PudData &pd, bool parsed, const char *path)
{
    if (!parsed) {
        printf("PARSE-FAILED\n");
        fflush(stdout);
        return;
    }
    gzFile out = gzopen(path, "wb");
    if (out == NULL) {
        fprintf(stderr, "fuzz_Parse: cannot open %s\n", path);
        abort();
    }
    pd.WriteSMP(out, NULL);
    pd.WriteSMS(out);
    gzclose(out);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    unsigned char* buf = (unsigned char*) malloc(sizeof(unsigned char) * 100);
    provider.ConsumeData(buf, sizeof(unsigned char) * 100);

    const char *dump = DumpPath();
    PudData pd;
    bool parsed;
    if (dump != NULL && size > 100) {
        parsed = pd.Parse(data, size);  // dump mode only: a whole map longer than 100 bytes
    } else {
        parsed = pd.Parse(buf, sizeof(unsigned char) * 100);
    }
    if (dump != NULL) {
        Dump(pd, parsed, dump);
    }

    free(buf);
    return 0;
}
