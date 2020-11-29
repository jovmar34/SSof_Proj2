#!/usr/bin/python3

import sys
import json
import ast_traverse
from collections import defaultdict

if (len(sys.argv) != 3):
    print("call format is: <slices>.json <vulns>.json") 

vulns = {}
with open(sys.argv[2]) as patterns_f:
    pat_json = json.load(patterns_f)
    for vuln in pat_json:
        vulns[vuln['vulnerability']] = {"sources": vuln['sources'],
        "sanitizers": vuln['sanitizers'],
        "sinks": vuln['sinks']}

print(vulns)

taints = defaultdict(list)
with open(sys.argv[1]) as slices_f:
    slice_json = json.load(slices_f)
    ast_traverse.work(vulns, slice_json)
