#!/usr/bin/python3

from argparse import ArgumentParser
import parser
from parsed_tree import LEFT, RIGHT, OP, OBJ, QUALS, OBJTYPE, PROTO
from code_objects import finalize, ProgramEncoder, loads_hook
from bpf_objects import CBPFCompilerState
import bpf_objects
import demo_objects
import json


def main():
    '''Parse a pcap expression and compile it into
    bpf
    '''
    aparser = ArgumentParser(description=main.__doc__)
    aparser.add_argument(
       '--expr',
        help='pcap expression',
        type=str
        )
    
    aparser.add_argument(
       '--format',
        help='output format',
        type=str,
        default="cbpf"
        )
    args = vars(aparser.parse_args())

    parsed = finalize(parser.PARSER.parse(args["expr"]))


    print(json.dumps(parsed, cls=ProgramEncoder, indent=4))

    parsed.add_helper(demo_objects.dispatcher)
    parsed.add_helper(bpf_objects.dispatcher)

    print("compile")

    parsed.compile(CBPFCompilerState())
    parsed.resolve_refs()

    print("BPF")

    counter = 0
    for inst in parsed.get_code("cbpf"):
        print("{} {}".format(counter, inst))
        counter += 1

    print("Offload simulation")

    counter = 0
    for inst in parsed.get_code("simulated offload"):
        print("{} {}".format(counter, inst))
        counter += 1



if __name__ == "__main__":
    main()

