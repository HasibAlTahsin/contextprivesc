#!/usr/bin/env python3
from utils.constants import GTFOBINS

def lookup(binary_name):
    binary = binary_name.lower()
    if binary in GTFOBINS:
        return {"binary": binary, "exploit": GTFOBINS[binary]}
    for key in GTFOBINS:
        if key in binary or binary in key:
            return {"binary": key, "exploit": GTFOBINS[key]}
    return None
