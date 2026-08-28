/*
 * mayhem/pudconvert_wrapper_main.cpp -- leak-free main() for the `pudconvert` fuzz target.
 *
 * WHY THIS EXISTS
 * Upstream's pudconvert.cpp main() leaks on EVERY successful conversion:
 *
 *     char *newname = strdup(infile);
 *     newname = basename(newname);      // <- overwrites the only pointer to the allocation
 *     ...
 *     PudToStratagus(buf, len, newname, outdir);
 *
 * glibc's basename() returns a pointer INTO its argument, so reassigning `newname` discards the
 * strdup'd block and nothing ever frees it (the `outdir` default path a few lines up has the same
 * strdup/dirname shape). Under the ASan+LSan build that is a 24-byte LeakSanitizer report at exit
 * on every valid input, i.e. a nonzero exit for every test case. Mayhem reads that as a crash:
 * run #2 died with "Your run failed because the target crashes on every test case in the test
 * suite and on the default test case" — Mayhem needs at least one PASSING test case to start, so
 * the target never fuzzed despite reaching 2829 edges.
 *
 * WHY NOT JUST SILENCE LSan
 * Both suppression routes are hard-failed by scripts/integration/verify-repo.sh, deliberately: a
 * Mayhemfile ASAN_OPTIONS REPLACES Mayhem's own runtime option set, and a compiled-in weak
 * sanitizer-default-options override under mayhem/ is banned outright ("all ASAN/LibFuzzer option
 * passing belongs to Mayhem, never the harness" -- on vorbis/muparser real runs came back healthy
 * once such an override was REMOVED). This file deliberately defines NO such override; the gate
 * greps mayhem/ for those two symbol names by content, so they are not spelled out here. Fixing
 * the leak itself is the honest fix.
 *
 * WHY NOT EDIT pudconvert.cpp
 * The integration must stay additive -- exactly one commit that only ADDS files, never modifies
 * upstream ones (pr-gate check 6 re-verifies this against the mirror). So this file is added and
 * linked INSTEAD of upstream's pudconvert.cpp, which contains nothing but main() and usage().
 *
 * SAME FUZZ SURFACE
 * The parser under test is PudToStratagus() in pud.cpp (PudData::Parse and everything it drives),
 * which is linked and called here exactly as upstream's main() calls it -- same buffer, same
 * length, same derived name, same output directory. Only main()'s argument/lifetime handling
 * differs, and only to free what upstream drops. mayhem/test.sh's behavioral oracle runs this same
 * binary (/mayhem/pudconvert), so the code it checks is the code the targets fuzz (issue #1460 A;
 * see mayhem/build.sh).
 */
#include <sys/stat.h>
#include <sys/types.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#include "pud.h"

int main(int argc, char **argv)
{
    if (argc < 2 || argc > 3) {
        std::fprintf(stderr, "usage: %s inputfile [outputdir]\n", argv[0]);
        return 1;
    }

    const char *infile = argv[1];

    struct stat sb;
    if (stat(infile, &sb) != 0) {
        std::fprintf(stderr, "error finding file: %s\n", infile);
        return -1;
    }
    const size_t len = static_cast<size_t>(sb.st_size);

    /* Output directory: argv[2] if given, else the input's directory. Upstream derives this with
     * strdup()+dirname() and leaks the block; std::string owns it and frees on scope exit. */
    std::string outdir;
    if (argc == 3) {
        outdir = argv[2];
    } else {
        const char *slash = std::strrchr(infile, '/');
        outdir = (slash == nullptr) ? "." : std::string(infile, static_cast<size_t>(slash - infile));
        if (outdir.empty()) {
            outdir = "/";   /* input was "/foo": dirname is the root, not "" */
        }
    }
    if (stat(outdir.c_str(), &sb) != 0) {
        std::fprintf(stderr, "error finding directory: %s\n", outdir.c_str());
        return -1;
    }

    std::FILE *f = std::fopen(infile, "rb");
    if (f == nullptr) {
        std::fprintf(stderr, "error opening file: %s\n", infile);
        return -1;
    }
    /* Upstream mallocs `len` and does not check the result; a std::string owns the buffer here so
     * every early return below frees it. A zero-length input still yields a valid pointer to pass
     * on, matching upstream's behaviour on an empty file. */
    std::string buf(len, '\0');
    const size_t got = (len == 0) ? 0 : std::fread(&buf[0], 1, len, f);
    if (std::ferror(f)) {
        std::fprintf(stderr, "error reading from file: %s\n", infile);
        std::fclose(f);
        return -1;
    }
    if (std::fclose(f) != 0) {
        std::fprintf(stderr, "error closing file: %s\n", infile);
        return -1;
    }
    buf.resize(got);

    /* Output basename: input's basename with a trailing ".pud" stripped -- the same transform
     * upstream applies, minus the leaked strdup. */
    const char *slash = std::strrchr(infile, '/');
    std::string name = (slash == nullptr) ? infile : slash + 1;
    const std::string::size_type dot = name.rfind(".pud");
    if (dot != std::string::npos) {
        name.erase(dot);
    }

    PudToStratagus(reinterpret_cast<const unsigned char *>(buf.data()), buf.size(),
                   name.c_str(), outdir.c_str());
    return 0;
}
