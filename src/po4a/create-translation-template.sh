#!/usr/bin/env sh

# Create the pot file from existing man pages.
# Don't forget to add newly created man pages here.

po4a-gettextize \
        --option groff_code=verbatim \
        --option untranslated="a.RE,\|" \
        --option unknown_macros=untranslated \
        -f man \
            -m ../lzmainfo/lzmainfo.1 \
            -m ../scripts/xzdiff.1 \
            -m ../scripts/xzgrep.1 \
            -m ../scripts/xzless.1 \
            -m ../scripts/xzmore.1 \
            -m ../xz/xz.1 \
            -m ../xzdec/xzdec.1 \
        -p xz-man.pot
