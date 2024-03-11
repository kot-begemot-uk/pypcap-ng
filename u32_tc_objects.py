''' Pure python implementation of the pcap language parser.
Compiler backends - U32TC.
'''


#
# Copyright (c) 2023 Red Hat, Inc., Anton Ivanov <anivanov@redhat.com>
# Copyright (c) 2023 Cambridge Greys Ltd <anton.ivanov@cambridgegreys.com>
#

import sys
import re
import ipaddress
from header_constants import ETHER, IP, IP6, ETH_PROTOS
from code_objects import AbstractCode, AbstractHelper


# Some of the names are predefined. They are instruction names. We
# should not change them.
#pylint: disable=line-too-long, invalid-name, consider-using-f-string


IPV4_REGEXP = re.compile(r"(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})")

def compute_val_mask(lower, upper):
    '''Compute value and mask approximation from lower/upper bounds'''
    valb = ""
    fill = True
    for bit in bin(lower)[:1:-1]:
        if fill and bit == "0":
            valb = bit + valb
        else:
            fill = False
            valb = "1" + valb
    val = int("0b" + valb, 2)
    maskb = bin(upper - val)
    if "0" in maskb[2:]:
        mask = (1 << (len(maskb) - 3)) - 1
    else:
        mask = (1 << (len(maskb) - 2)) - 1
    return val, mask



SIZE_MODS = [None, "u8", "u16", None, "u32"]

# U32TC instruction as described in the literature is not an instruction
# when using our abstractions. It is a mini-program which consists f
# LD (absolute or index), SHL or SHR, AND and a comparison - a total
# of four instructions

LD_OP = 0
SH_OP = 1
AND_OP = 2
COMP_OP = 3

class U32TCCode(AbstractCode):
    '''U32TC variant of code generation'''
    def __init__(self, sel_type, selector, size=4, val=0, mask=0, at=None):
        super().__init__()
        self.sel_type = sel_type
        self.selector = selector
        self.val = val
        self.mask = mask
        self.size = size
        self.at = at

    def validate(self):
        '''Perform validation of the values supplied to the constructor'''
        check = 1 << self.size
        if check < self.val or check < self.mask:
            raise ValueError("Argument size exceeded")

    def obj_dump(self, counter):
        '''Dump bytecode'''
        return f"{counter} {self}\n"

    def __repr__(self):
        '''Same as repr'''
        return f"{self}"

    def __str__(self):
        '''Printable form of U32TC instructions'''

        if self.sel_type is None:
            return f"match {self.selector} 0x{self.val:x} 0x{self.mask:x} at {self.at}"

        if self.mask != 0:
            ret = f"match {self.sel_type} {self.selector} 0x{self.val:x} 0x{self.mask:x}"
        else:
            ret = f"match {self.sel_type} {self.selector}"
        if self.at is not None:
            ret += " at {self.at}"
        return ret

V4_NET_REGEXP = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\/(\d{1,2})")

class U32TCHelper(AbstractHelper):
    '''U32TC variant of AbstractHelper'''

    def __init__(self, pcap_obj=None):
        super().__init__(pcap_obj)
        self.helper_id = "u32tc"

    def dump_code(self, fmt, options):
        '''Dump U32'''

        super().dump_code(fmt, options)

        res = []

        for insn in self.get_code():
            res.append(f"{insn}")

        return " ".join(res) 


    @property
    def offset(self):
        '''match_object getter'''
        try:
            return self.attribs["offset"]
        except KeyError:
            return 0


    @property
    def loc(self):
        '''match_object getter'''
        return self.pcap_obj.loc


    @property
    def match_object(self):
        '''match_object getter'''
        return self.attribs["match_object"]

    @property
    def on_success(self):
        '''on_success getter'''
        return self.attribs["on_success"]

    @property
    def on_failure(self):
        '''on_failure getter'''
        return self.attribs["on_failure"]

    @property
    def attribs(self):
        '''attribs getter'''
        return self.pcap_obj.attribs

    @property
    def frags(self):
        '''frags getter'''
        return self.pcap_obj.frags

    @property
    def left(self):
        '''left getter'''
        return self.pcap_obj.left

    @property
    def right(self):
        '''right getter'''
        return self.pcap_obj.right

    @property
    def ip_version(self):
        '''right getter'''
        return self.pcap_obj.ip_version

class U32TCProgL3(U32TCHelper):
    '''Layer 3 protocol matcher'''
    def compile(self, compiler_state=None):
        '''Compile the code'''
        super().compile(compiler_state)
        self.add_code([U32TCCode(
            None,
            "u8",
            None,
            val=int(self.match_object),
            mask=0xFF,
            at=9
        )])

class U32TCProgTCP(U32TCProgL3):
    '''Basic match on IP - any shape or form,
       added before matching on address, proto, etc.
    '''

class U32TCProgIPAny(U32TCHelper):
    '''Basic match on v4 address or network.
    '''
    def compile(self, compiler_state=None):
        '''Generate the actual code for the match'''
        try:
            addr = ipaddress.ip_address(self.match_object)
        except ValueError:
            # we let it raise a value error in this case
            addr = ipaddress.ip_network(self.match_object)

        # we do not do any further checks, because regexps
        # should narrow the input to ip_address sufficiently
        # to guarantee a v4 of some sort.


        super().compile(compiler_state)

        if "srcordst" in self.pcap_obj.quals or "srcanddst" in self.pcap_obj.quals:
            return
        if "src" in self.pcap_obj.quals:
            qual = "src"
        elif "dst" in self.pcap_obj.quals:
            qual = "dst"
        else:
            raise ValueError("Must specify src or dst")

        self.add_code([U32TCCode(
            "ip",
            f"{qual} {addr}"
        )])


class U32TCProgIPv4(U32TCProgIPAny):
    '''Basic match on v6 address or network.
    '''

class U32TCProgIPv6(U32TCProgIPAny):
    '''Basic match on v6 address or network.
    '''

class U32TCProgNOT(U32TCHelper):
    '''Negate the result of all frags.
    '''
    def compile(self, compiler_state=None):
        '''Compile NOT - inverse true and false'''
        raise ValueError("NOT not supported in U32TC")


class U32TCProgOR(U32TCHelper):
    '''Perform logical OR on left and right frag(s)
    '''
    def compile(self, compiler_state=None):
        '''Compile OR - inverse true and false'''
        raise ValueError("NOT not supported in U32TC")

class U32TCProgPortRange(U32TCHelper):
    '''Basic match on IP - any shape or form,
       added before matching on address, proto, etc.
    '''
    def compile(self, compiler_state=None):
        '''Compile the code'''

        super().compile(compiler_state)

        try:
            left = self.attribs["loc"][0]
            try:
                right = self.attribs["loc"][1]
            except IndexError:
                right = left
            left.compile(compiler_state)
            right.compile(compiler_state)
        except KeyError:
            left = right = self.pcap_obj.frags[0]

        if left.result is None or right.result is None:
            raise ValueError("U32 does not allow dynamic offset computation")

        (value, mask) = compute_val_mask(left.result, right.result)

        location = 0

        if "src" in self.pcap_obj.quals:
            self.add_code([U32TCCode(
                None,
                "u16",
                "",
                val=value,
                mask=mask,
                at=f"nexthrdr+ {location}"
            )])

        if "dst" in self.pcap_obj.quals:
            location = location + 2
            self.add_code([U32TCCode(
                None,
                "u16",
                "",
                val=value,
                mask=mask,
                at=f"nexthrdr+ {location}"
            )])

class U32ProgLoad(U32TCHelper):
    '''Load a value from packet address
    '''

class U32TCProgIndexLoad(U32TCHelper):
    '''Perform arithmetic operations.
    '''

COMPUTE_TABLE = {
    "+" : lambda x, y: x + y,
    "-" : lambda x, y: x - y,
    "*" : lambda x, y: x * y,
    "/" : lambda x, y: x / y,
    "%" : lambda x, y: x % y,
    "&" : lambda x, y: x & y,
    "|" : lambda x, y: x | y,
    "^" : lambda x, y: x ^ y,
    "<<" : lambda x, y: x << y,
    ">>" : lambda x, y: x >> y,
    "<" : lambda x, y: x < y,
    ">" : lambda x, y: x > y,
    "==" : lambda x, y: x == y,
    "!=" : lambda x, y: not x == y,
    ">=" : lambda x, y: x >= y,
    "<=" : lambda x, y: x <= y
}


def compute(left, op, right):
    '''Dumb calculcator'''
    return COMPUTE_TABLE[op](left, right)


class U32TCProgComp(U32TCHelper):
    '''Perform arithmetic comparisons.
    '''

    def compile(self, compiler_state=None):
        '''Compile comparison between operands'''

        left = self.pcap_obj.left
        right = self.pcap_obj.right

        super().compile(compiler_state)

        if left.result is not None and right.result is not None:
            self.pcap_obj.result = compute(left.result, self.attribs["op"], right.result)
            return

        if right.result is None:
            raise ValueError("Only static expressions are allowed for values")
        try:
            location = left.attribs["loc"].attribs["match_object"]
        except AttributeError:
            location = int(left.attribs["loc"])

        try:
            size = left.attribs["size"]
        except KeyError:
            size = 4

        if self.attribs["op"] == "==":
            self.add_code([U32TCCode(
                None,
                "u{}".format(size * 8),
                "",
                val=int(right.result),
                mask=(1 << size*8) - 1,
                at=f"nexthrdr+ {location}"
            )])


class U32TCImmediate(U32TCHelper):
    '''Fake leafe for immediate ops
    '''
    def compile(self, compiler_state=None):
        self.pcap_obj.result = self.match_object

class U32TCProgArOp(U32TCHelper):
    '''Perform arithmetic operations.
    '''

    def compile(self, compiler_state=None):
        '''Compile arithmetics'''

        left = self.pcap_obj.left
        right = self.pcap_obj.right

        super().compile(compiler_state)

        if self.left.result is not None and self.right.result is not None:
            self.pcap_obj.result = compute(left.result, self.attribs["op"], right.result)



def dispatcher(obj):
    '''Return the correct code helper'''
    try:
        return getattr(sys.modules[__name__], f"U32TC{obj.__class__.__name__}")(obj)
    except (KeyError, AttributeError):
        return U32TCHelper(obj)
