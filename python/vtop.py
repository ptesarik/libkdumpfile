#!/usr/bin/env python
# vim:sw=4 ts=4 et

from __future__ import print_function
import kdumpfile
import addrxlat
from sys import argv

tbl_names = ( 'PAGE', 'PTE', 'PMD', 'PUD', 'PGD' )

class kphysnote(object):
    def __init__(self, ctx, sys):
        self.ctx = ctx
        self.sys = sys

        map = sys.get_map(addrxlat.SYS_MAP_MACHPHYS_KPHYS)
        self.ident = True
        for range in map:
            if range.meth is None:
                continue
            desc = range.meth.get_desc()
            if desc.kind != addrxlat.LINEAR or desc.off != 0:
                self.ident = False
                break

    def note(self, fulladdr, fmt='{}'):
        if self.ident or fulladdr.addrspace == addrxlat.KPHYSADDR:
            return ''
        tmp = fulladdr.copy()
        try:
            tmp.conv(addrxlat.KPHYSADDR, self.ctx, self.sys)
            return fmt.format('{:x}'.format(tmp.addr))
        except (addrxlat.NotPresentError, addrxlat.NoDataError):
            return fmt.format('N/A')

def vtop(addr, ctx, sys):
    fulladdr = addrxlat.FullAddress(addrxlat.KVADDR, addr)
    print('{:16}  {:16}'.format('VIRTUAL', 'PHYSICAL'))
    try:
        fulladdr.conv(addrxlat.KPHYSADDR, ctx, sys)
        print('{:<16x}  {:<16x}\n'.format(addr, fulladdr.addr))
    except addrxlat.BaseException:
        print('{:<16x}  {:<16}\n'.format(addr, '---'))

    step = addrxlat.Step(ctx, sys)
    meth = sys.get_map(addrxlat.SYS_MAP_HW).search(addr)
    if meth is None:
        meth = sys.get_map(addrxlat.SYS_MAP_KV_PHYS).search(addr)
    if meth is None:
        print('NO METHOD')
        return

    note = kphysnote(ctx, sys)
    while step.remain:
        tbl = tbl_names[step.remain - 1]
        if step.remain > 1:
            addr = step.base.copy()
            addr.addr += step.idx[step.remain - 1] * step.elemsz
        else:
            addr = step.base
        remark = note.note(addr, ' ({})')
        print('{:>4}: {:16x}{}'.format(tbl, addr.addr, remark), end='')

        try:
            step.step()
            if step.remain and step.raw is not None:
                print(' => {:x}'.format(step.raw))
        except addrxlat.NotPresentError:
            print(' => {:x}  NOT PRESENT'.format(step.raw))
            return
    print()

if len(argv) != 3:
    print('Usage: {} <dumpfile> <virtual address>'.format(argv[0]))
    exit(1)

kdf = kdumpfile.kdumpfile(argv[1])
kdf.addrxlat_convert = addrxlat.convert
kdf.attr['addrxlat.ostype'] = 'linux'
sys = kdf.get_addrxlat_sys()
ctx = kdf.get_addrxlat_ctx()

addr = int(argv[2], base=0)
try:
    vtop(addr, ctx, sys)
except addrxlat.BaseException as e:
    print('Translation failed: {}'.format(e.message))
