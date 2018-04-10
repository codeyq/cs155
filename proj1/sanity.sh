#!/bin/bash

RST="$(tput sgr 0)"
FR="$(tput setaf 1)"
FG="$(tput setaf 2)"
FY="$(tput setaf 3)"
BD="$(tput bold)"

# ID.csv
ORIG_SHA1="ec6472bc86f35868a8c7cd8b97235a1311433da1"
SHA1="$(sha1sum ID.csv | cut -d' ' -f1)"
if [ "$SHA1" == "$ORIG_SHA1" ]; then
    echo "${BD}${FR}fill in ID.csv${RST}"
fi

# Parts 1 and 2
for ((i=1; i<=6; i++)); do
    if [ ! -f sploits/sploit$i ]; then
        RESULT="${FR}not found${RST}"
    else
        USER="$(echo "whoami" | sploits/sploit$i)"
        RC=$?
        if [ $RC -ne 0 ]; then
            RESULT="${FR}unexpected exit code $RC${RST}"
        elif [ "$USER" != "root" ]; then
            RESULT="${FR}fail${RST}"
        else
            RESULT="${FG}pass${RST}"
        fi
    fi
    echo "${BD}sploit$i${RST}: $RESULT"
done

# Part 3
if [ ! -f fuzz/install/bin/bsdtar ]; then
    RESULT="${FR}bsdtar not found${RST}"
elif [ ! -f fuzz/results/crashes/id:000000* ]; then
    RESULT="${FR}no crashes found${RST}"
else
    { fuzz/install/bin/bsdtar -O -xf fuzz/results/crashes/id:000000*; } &>/dev/null
    RC=$?
    if [ $RC -le 128 ] || [ $RC -ge 160 ]; then
        RESULT="${FR}non-crash: exit code $RC${RST}"
    else
        RESULT="${FG}crash: exit code $RC${RST}"
    fi
fi
echo "${BD}fuzz bsdtar${RST}: $RESULT"
ORIG_SHA1="f792a23a2460500baadca8030d126e193abdc964"
SHA1="$(sha1sum fuzz/README | cut -d' ' -f1)"
if [ "$SHA1" == "$ORIG_SHA1" ]; then
    echo "${BD}${FR}fill in fuzz/README${RST}"
fi

# Extra credit
if [ -f sploits/extra-credit.txt ]; then
    RESULT="${FG}present${RST}"
else
    RESULT="${FY}not present${RST}"
fi
echo "${BD}extra credit${RST}: $RESULT"
