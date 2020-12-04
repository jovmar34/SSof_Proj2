#!/usr/bin/python3

import sys
import json
import ast_traverse
from collections import defaultdict

if (len(sys.argv) != 3):
    print("call format is: <slices>.json <vulns>.json") 

vulns = defaultdict(list)
with open(sys.argv[2]) as patterns_f:
    pat_json = json.load(patterns_f)
    for vuln in pat_json:
        for source in vuln['sources']:
            vulns[source] += [(vuln['vulnerability'], vuln['sinks'], vuln['sanitizers'])]

#print(vulns)

output_file_name = sys.argv[1].split(".")[0].split("/")[-1] + ".output.json"
print(output_file_name)

with open(sys.argv[1]) as slices_f:
    slice_json = json.load(slices_f)
    ast_traverse.build_tree(vulns, slice_json, output_file_name)