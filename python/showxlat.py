#!/usr/bin/env python
# vim:sw=4 ts=4 et

# A version of examples/showxlat.c translated to Python.
# The script is not meant to be particularly useful, but it should
# demonstrate use of the libaddrxlat Python API.
#
# This file is in public domain.

from __future__ import print_function

import sys
import kdumpfile
import addrxlat

def addrspace_str(addrspace):
    if addrspace == addrxlat.KPHYSADDR:
        return 'KPHYSADDR'
    elif addrspace == addrxlat.MACHPHYSADDR:
        return 'MACHPHYSADDR'
    elif addrspace == addrxlat.KVADDR:
        return 'KVADDR'
    elif addrspace == addrxlat.NOADDR:
        return 'NOADDR'
    else:
        return '<addrspace {:d}>'.format(addrspace)

def fulladdr_str(addr):
    result = addrspace_str(addr.addrspace)
    if addr.addrspace != addrxlat.NOADDR:
        result += ':0x{:x}'.format(addr.addr)
    return result

def print_target_as(desc):
    print('  target_as={}'.format(addrspace_str(desc.target_as)))

def print_linear(desc):
    print('LINEAR')
    print_target_as(desc)
    print('  off=0x{:x}'.format(desc.off))

pte_formats = {
    addrxlat.PTE_NONE: 'none',
    addrxlat.PTE_PFN32: 'pfn32',
    addrxlat.PTE_PFN64: 'pfn64',
    addrxlat.PTE_IA32: 'ia32',
    addrxlat.PTE_IA32_PAE: 'ia32_pae',
    addrxlat.PTE_X86_64: 'x86_64',
    addrxlat.PTE_S390X: 's390x',
    addrxlat.PTE_PPC64_LINUX_RPN30: 'ppc64_linux_rpn30',
}

def print_pgt(desc):
    print('PGT')
    print_target_as(desc)
    print('  root={}'.format(fulladdr_str(desc.root)))
    fmt = pte_formats.get(desc.pte_format, desc.pte_format)
    print('  pte_format={}'.format(fmt))
    print('  fields={}'.format(','.join(str(i) for i in desc.fields)))

def print_lookup(desc):
    print('LOOKUP')
    print_target_as(desc)
    print('  endoff=0x{:x}'.format(desc.endoff))
    for elem in desc.tbl:
        print('  {:x} -> {:x}'.format(elem[0], elem[1]))

def print_memarr(desc):
    print('MEMARR')
    print_target_as(desc)
    print('  base={}'.format(fulladdr_str(desc.base)))
    print('  shift={}'.format(desc.shift))
    print('  elemsz={}'.format(desc.elemsz))
    print('  valsz={}'.format(desc.valsz))

def print_desc(desc):
    if desc.kind == addrxlat.NOMETH:
        print('NOMETH')
    elif desc.kind == addrxlat.CUSTOM:
        print('CUSTOM')
    elif desc.kind == addrxlat.LINEAR:
        print_linear(desc)
    elif desc.kind == addrxlat.PGT:
        print_pgt(desc)
    elif desc.kind == addrxlat.LOOKUP:
        print_lookup(desc)
    elif desc.kind == addrxlat.MEMARR:
        print_memarr(desc)
    else:
        print('<desc kind {:d}>'.format(desc.kind))

def add_meth(name, meth):
    if meth is not None:
        meths[name] = meth
        print('METH_{}: '.format(name), end='')
        print_desc(meth.get_desc())
        print()

def print_meth(meth):
    if meth is None:
        print('NONE')
        return

    for (k, v) in meths.items():
        if v == meth:
            print(k)
            return

    print(repr(meth), end=' ')
    print_desc(meth.get_desc())

def print_map(name, map):
    print(format(name), end=':\n')

    if map is None:
        return

    addr = 0
    for range in map:
        print('{:x}-{:x}: '.format(addr, addr + range.endoff), end='')
        print_meth(range.meth)
        addr += range.endoff + 1

def dump_addrxlat(ctx):
    system = k.get_addrxlat_sys()

    add_meth('PGT', system.get_meth(addrxlat.SYS_METH_PGT))
    add_meth('UPGT', system.get_meth(addrxlat.SYS_METH_UPGT))
    add_meth('DIRECT', system.get_meth(addrxlat.SYS_METH_DIRECT))
    add_meth('KTEXT', system.get_meth(addrxlat.SYS_METH_KTEXT))
    add_meth('VMEMMAP', system.get_meth(addrxlat.SYS_METH_VMEMMAP))
    add_meth('RDIRECT', system.get_meth(addrxlat.SYS_METH_RDIRECT))
    add_meth('MACHPHYS_KPHYS', system.get_meth(addrxlat.SYS_METH_MACHPHYS_KPHYS))
    add_meth('KPHYS_MACHPHYS', system.get_meth(addrxlat.SYS_METH_KPHYS_MACHPHYS))

    print_map('MAP_HW', system.get_map(addrxlat.SYS_MAP_HW))
    print()
    print_map('MAP_KV_PHYS', system.get_map(addrxlat.SYS_MAP_KV_PHYS))
    print()
    print_map('MAP_KPHYS_DIRECT', system.get_map(addrxlat.SYS_MAP_KPHYS_DIRECT))
    print()
    print_map('MACHPHYS -> KPHYS', system.get_map(addrxlat.SYS_MAP_MACHPHYS_KPHYS))
    print()
    print_map('KPHYS -> MACHPHYS', system.get_map(addrxlat.SYS_MAP_KPHYS_MACHPHYS))

meths = dict()

if __name__ == '__main__':
    if len(sys.argv) < 2 or len(sys.argv) > 3:
        print('Usage: {} <dumpfile> [<ostype>]'.format(sys.argv[0]),
              file=sys.stderr)
        exit(1)

    k = kdumpfile.kdumpfile(sys.argv[1])

    if len(sys.argv) > 2:
        k.attr['addrxlat.ostype'] = sys.argv[2]

    dump_addrxlat(k)
