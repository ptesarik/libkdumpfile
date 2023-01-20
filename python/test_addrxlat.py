#!/usr/bin/env python
# vim:sw=4 ts=4 et

import unittest
import addrxlat
import sys

if (sys.version_info.major >= 3):
    xrange = range

class TestAddressSpace(unittest.TestCase):
    names = (
        'KPHYSADDR',
        'MACHPHYSADDR',
        'KVADDR',
        'NOADDR',
    )

    def test_addrspace_name(self):
        for name in self.names:
            self.assertEqual(addrxlat.addrspace_name(addrxlat.__dict__[name]),
                             name)

class TestFullAddress(unittest.TestCase):
    def test_fulladdr_defaults(self):
        addr = addrxlat.FullAddress()
        self.assertEqual(addr.addrspace, addrxlat.NOADDR)
        self.assertEqual(addr.addr, 0)

    def test_fulladdr_addrspace(self):
        addr = addrxlat.FullAddress(addrspace=addrxlat.KVADDR)
        self.assertEqual(addr.addrspace, addrxlat.KVADDR)
        self.assertEqual(addr.addr, 0)

    def test_fulladdr_addr(self):
        addr = addrxlat.FullAddress(addr=0xabcd)
        self.assertEqual(addr.addrspace, addrxlat.NOADDR)
        self.assertEqual(addr.addr, 0xabcd)

    def test_fulladdr_init_pos(self):
        addr = addrxlat.FullAddress(addrxlat.KVADDR, 0xabcd)
        self.assertEqual(addr.addrspace, addrxlat.KVADDR)
        self.assertEqual(addr.addr, 0xabcd)

    def test_fulladdr_init_kwarg(self):
        addr = addrxlat.FullAddress(addr=0xabcd, addrspace=addrxlat.KVADDR)
        self.assertEqual(addr.addrspace, addrxlat.KVADDR)
        self.assertEqual(addr.addr, 0xabcd)

    def test_fulladdr_eq(self):
        addr1 = addrxlat.FullAddress(addrxlat.KVADDR, 0x1234)
        addr2 = addrxlat.FullAddress(addrxlat.KVADDR, 0x1234)
        self.assertEqual(addr1, addr2)

    def test_fulladdr_noteq(self):
        addr1 = addrxlat.FullAddress(addrxlat.KVADDR, 0x1234)
        addr2 = addrxlat.FullAddress(addrxlat.KVADDR, 0xabcd)
        self.assertNotEqual(addr1, addr2)

    def test_fulladdr_copy(self):
        addr1 = addrxlat.FullAddress(addrxlat.KVADDR, 0x1234)
        addr2 = addr1.copy()
        self.assertIsInstance(addr2, addrxlat.FullAddress)
        self.assertEqual(addr1.addrspace, addr2.addrspace)
        self.assertEqual(addr1.addr, addr2.addr)

    def test_fulladdr_copy_subclass(self):
        class myfulladdr(addrxlat.FullAddress):
            pass

        addr1 = myfulladdr(addrxlat.KVADDR, 0x1234)
        addr2 = addr1.copy()
        self.assertIsInstance(addr2, myfulladdr)

class TestContext(unittest.TestCase):
    def test_err(self):
        ctx = addrxlat.Context()
        ctx.clear_err()
        self.assertIs(ctx.get_err(), None)
        status = ctx.err(addrxlat.ERR_CUSTOM_BASE, 'An error message')
        self.assertEqual(status, addrxlat.ERR_CUSTOM_BASE)
        self.assertEqual(ctx.get_err(), 'An error message')
        ctx.clear_err()
        self.assertIs(ctx.get_err(), None)

class TestMethod(unittest.TestCase):
    def test_meth_defaults(self):
        meth = addrxlat.Method(addrxlat.NOMETH)
        self.assertEqual(meth.kind, addrxlat.NOMETH)
        self.assertEqual(meth.target_as, addrxlat.NOADDR)
        for i in xrange(len(meth.param)):
            self.assertEqual(meth.param[i], 0)

    def test_meth_readonly_kind(self):
        meth = addrxlat.Method(addrxlat.NOMETH)
        with self.assertRaises(AttributeError):
            meth.kind = addrxlat.LINEAR

    def test_meth_target_as(self):
        meth = addrxlat.Method(addrxlat.NOMETH, addrxlat.MACHPHYSADDR)
        self.assertEqual(meth.kind, addrxlat.NOMETH)
        self.assertEqual(meth.target_as, addrxlat.MACHPHYSADDR)
        for i in xrange(len(meth.param)):
            self.assertEqual(meth.param[i], 0)

    def test_meth_param(self):
        meth = addrxlat.Method(addrxlat.NOMETH, param=(0, 1, 2, 3))
        self.assertGreaterEqual(len(meth.param), 4)
        self.assertEqual(meth.kind, addrxlat.NOMETH)
        self.assertEqual(meth.target_as, addrxlat.NOADDR)
        for i in xrange(4):
            self.assertEqual(meth.param[i], i)
        for i in xrange(4, len(meth.param)):
            self.assertEqual(meth.param[i], 0)

        for i in xrange(4):
            meth.param[i] += 1
        self.assertEqual(meth.kind, addrxlat.NOMETH)
        self.assertEqual(meth.target_as, addrxlat.NOADDR)
        for i in xrange(4):
            self.assertEqual(meth.param[i], i + 1)
        for i in xrange(4, len(meth.param)):
            self.assertEqual(meth.param[i], 0)

        with self.assertRaises(OverflowError):
            meth.param[0] = 999
        with self.assertRaises(OverflowError):
            meth.param[0] = -1

    def test_custom_defaults(self):
        meth = addrxlat.CustomMethod()
        self.assertEqual(meth.kind, addrxlat.CUSTOM)
        self.assertEqual(meth.target_as, addrxlat.NOADDR)

    def test_custom_readonly_kind(self):
        meth = addrxlat.CustomMethod()
        with self.assertRaises(AttributeError):
            meth.kind = addrxlat.NOMETH

    def test_custom_target_as(self):
        meth = addrxlat.CustomMethod(addrxlat.MACHPHYSADDR)
        self.assertEqual(meth.kind, addrxlat.CUSTOM)
        self.assertEqual(meth.target_as, addrxlat.MACHPHYSADDR)

    def test_custom_notimpl(self):
        meth = addrxlat.CustomMethod(addrxlat.MACHPHYSADDR)
        self.assertEqual(meth.kind, addrxlat.CUSTOM)
        self.assertEqual(meth.target_as, addrxlat.MACHPHYSADDR)
        ctx = addrxlat.Context()
        step = addrxlat.Step(ctx=ctx, meth=meth)
        with self.assertRaisesRegex(BaseException, "NULL callback"):
            meth.cb_first_step(step, 0x1234)
        with self.assertRaisesRegex(BaseException, "NULL callback"):
            meth.cb_next_step(step)

    def test_linear_defaults(self):
        meth = addrxlat.LinearMethod()
        self.assertEqual(meth.kind, addrxlat.LINEAR)
        self.assertEqual(meth.target_as, addrxlat.NOADDR)
        self.assertEqual(meth.off, 0)

    def test_linear_readonly_kind(self):
        meth = addrxlat.LinearMethod()
        with self.assertRaises(AttributeError):
            meth.kind = addrxlat.NOMETH

    def test_linear_target_as(self):
        meth = addrxlat.LinearMethod(addrxlat.MACHPHYSADDR)
        self.assertEqual(meth.kind, addrxlat.LINEAR)
        self.assertEqual(meth.target_as, addrxlat.MACHPHYSADDR)
        self.assertEqual(meth.off, 0)

    def test_linear_off(self):
        meth = addrxlat.LinearMethod(off=addrxlat.ADDR_MAX - 0x1234)
        self.assertEqual(meth.kind, addrxlat.LINEAR)
        self.assertEqual(meth.target_as, addrxlat.NOADDR)
        self.assertEqual(meth.off, addrxlat.ADDR_MAX - 0x1234)

    def test_linear_neg_off(self):
        meth = addrxlat.LinearMethod(off=-addrxlat.ADDR_MAX)
        self.assertEqual(meth.kind, addrxlat.LINEAR)
        self.assertEqual(meth.target_as, addrxlat.NOADDR)
        self.assertEqual(meth.off, 1)

    def test_linear_param(self):
        meth = addrxlat.LinearMethod(off=0x1234)
        param = tuple(meth.param)
        self.assertLess(param.index(0x34), len(meth.param))
        meth.param = (0xff,) * len(meth.param)
        self.assertNotEqual(meth.off, 0x1234)

    def test_pgt_defaults(self):
        meth = addrxlat.PageTableMethod()
        self.assertEqual(meth.kind, addrxlat.PGT)
        self.assertEqual(meth.target_as, addrxlat.NOADDR)
        self.assertIs(meth.root, None)
        self.assertEqual(meth.pte_format, addrxlat.PTE_NONE)
        self.assertEqual(meth.fields, tuple())

    def test_pgt_readonly_kind(self):
        meth = addrxlat.PageTableMethod()
        with self.assertRaises(AttributeError):
            meth.kind = addrxlat.NOMETH

    def test_pgt_target_as(self):
        meth = addrxlat.PageTableMethod(addrxlat.MACHPHYSADDR)
        self.assertEqual(meth.kind, addrxlat.PGT)
        self.assertEqual(meth.target_as, addrxlat.MACHPHYSADDR)
        self.assertIs(meth.root, None)
        self.assertEqual(meth.pte_format, addrxlat.PTE_NONE)
        self.assertEqual(meth.fields, tuple())

    def test_pgt_root(self):
        root = addrxlat.FullAddress(addrxlat.MACHPHYSADDR, 0x1000)
        meth = addrxlat.PageTableMethod(root=root)
        self.assertEqual(meth.kind, addrxlat.PGT)
        self.assertEqual(meth.target_as, addrxlat.NOADDR)
        self.assertEqual(meth.root, root)
        self.assertEqual(meth.pte_format, addrxlat.PTE_NONE)
        self.assertEqual(meth.fields, tuple())

    def test_pgt_pte_format(self):
        meth = addrxlat.PageTableMethod(pte_format=addrxlat.PTE_PFN32)
        self.assertEqual(meth.kind, addrxlat.PGT)
        self.assertEqual(meth.target_as, addrxlat.NOADDR)
        self.assertIs(meth.root, None)
        self.assertEqual(meth.pte_format, addrxlat.PTE_PFN32)
        self.assertEqual(meth.fields, tuple())

    def test_pgt_fields(self):
        meth = addrxlat.PageTableMethod(fields=(1, 2, 3))
        self.assertEqual(meth.kind, addrxlat.PGT)
        self.assertEqual(meth.target_as, addrxlat.NOADDR)
        self.assertIs(meth.root, None)
        self.assertEqual(meth.pte_format, addrxlat.PTE_NONE)
        self.assertEqual(meth.fields, (1, 2, 3))

        meth.fields = (4, 5, 6)
        self.assertEqual(meth.fields, (4, 5, 6))
        with self.assertRaisesRegex(TypeError, 'not a sequence'):
            meth.fields = None
        with self.assertRaisesRegex(ValueError,
                                     'more than [0-9]+ address fields'):
            meth.fields = (0,) * (addrxlat.FIELDS_MAX + 1)

    def test_lookup_defaults(self):
        meth = addrxlat.LookupMethod()
        self.assertEqual(meth.kind, addrxlat.LOOKUP)
        self.assertEqual(meth.target_as, addrxlat.NOADDR)
        self.assertEqual(meth.endoff, 0)
        self.assertEqual(meth.tbl, tuple())

    def test_lookup_readonly_kind(self):
        meth = addrxlat.LookupMethod()
        with self.assertRaises(AttributeError):
            meth.kind = addrxlat.NOMETH

    def test_lookup_target_as(self):
        meth = addrxlat.LookupMethod(addrxlat.MACHPHYSADDR)
        self.assertEqual(meth.kind, addrxlat.LOOKUP)
        self.assertEqual(meth.target_as, addrxlat.MACHPHYSADDR)
        self.assertEqual(meth.endoff, 0)
        self.assertEqual(meth.tbl, tuple())

    def test_lookup_endoff(self):
        meth = addrxlat.LookupMethod(endoff=0x1234)
        self.assertEqual(meth.kind, addrxlat.LOOKUP)
        self.assertEqual(meth.target_as, addrxlat.NOADDR)
        self.assertEqual(meth.endoff, 0x1234)
        self.assertEqual(meth.tbl, tuple())

    def test_lookup_tbl(self):
        meth = addrxlat.LookupMethod(tbl=((0, 100), (200, 300)))
        self.assertEqual(meth.kind, addrxlat.LOOKUP)
        self.assertEqual(meth.target_as, addrxlat.NOADDR)
        self.assertEqual(meth.endoff, 0)
        self.assertEqual(meth.tbl, ((0, 100), (200, 300)))

        with self.assertRaisesRegex(TypeError, 'not a sequence'):
            meth.tbl = None
        with self.assertRaisesRegex(TypeError, 'not a sequence'):
            meth.tbl = (None,)
        with self.assertRaisesRegex(TypeError, 'not a sequence'):
            meth.tbl = 1
        with self.assertRaisesRegex(TypeError, 'not a sequence'):
            meth.tbl = (1,)
        with self.assertRaisesRegex(ValueError, 'must be integer pairs'):
            meth.tbl = ((),)
        with self.assertRaisesRegex(ValueError, 'must be integer pairs'):
            meth.tbl = ((1,),)
        with self.assertRaisesRegex(ValueError, 'must be integer pairs'):
            meth.tbl = ((1, 2, 3),)
        with self.assertRaisesRegex(TypeError, 'must be.* a .*number'):
            meth.tbl = ((None, None),)
        with self.assertRaisesRegex(TypeError, 'must be.* a .*number'):
            meth.tbl = ((1, None),)
        with self.assertRaisesRegex(TypeError, 'must be.* a .*number'):
            meth.tbl = ((None, 1),)

    def test_memarr_defaults(self):
        meth = addrxlat.MemoryArrayMethod()
        self.assertEqual(meth.kind, addrxlat.MEMARR)
        self.assertEqual(meth.target_as, addrxlat.NOADDR)
        self.assertEqual(meth.base, None)
        self.assertEqual(meth.shift, 0)
        self.assertEqual(meth.elemsz, 0)
        self.assertEqual(meth.valsz, 0)

    def test_memarr_readonly_kind(self):
        meth = addrxlat.MemoryArrayMethod()
        with self.assertRaises(AttributeError):
            meth.kind = addrxlat.NOMETH

    def test_memarr_target_as(self):
        meth = addrxlat.MemoryArrayMethod(addrxlat.MACHPHYSADDR)
        self.assertEqual(meth.kind, addrxlat.MEMARR)
        self.assertEqual(meth.target_as, addrxlat.MACHPHYSADDR)
        self.assertEqual(meth.base, None)
        self.assertEqual(meth.shift, 0)
        self.assertEqual(meth.elemsz, 0)
        self.assertEqual(meth.valsz, 0)

    def test_memarr_base(self):
        base = addrxlat.FullAddress(addrxlat.MACHPHYSADDR, 0x1234)
        meth = addrxlat.MemoryArrayMethod(base=base)
        self.assertEqual(meth.kind, addrxlat.MEMARR)
        self.assertEqual(meth.target_as, addrxlat.NOADDR)
        self.assertEqual(meth.base, base)
        self.assertEqual(meth.shift, 0)
        self.assertEqual(meth.elemsz, 0)
        self.assertEqual(meth.valsz, 0)

    def test_memarr_shift(self):
        meth = addrxlat.MemoryArrayMethod(shift=3)
        self.assertEqual(meth.kind, addrxlat.MEMARR)
        self.assertEqual(meth.target_as, addrxlat.NOADDR)
        self.assertEqual(meth.base, None)
        self.assertEqual(meth.shift, 3)
        self.assertEqual(meth.elemsz, 0)
        self.assertEqual(meth.valsz, 0)

    def test_memarr_elemsz(self):
        meth = addrxlat.MemoryArrayMethod(elemsz=12)
        self.assertEqual(meth.kind, addrxlat.MEMARR)
        self.assertEqual(meth.target_as, addrxlat.NOADDR)
        self.assertEqual(meth.base, None)
        self.assertEqual(meth.shift, 0)
        self.assertEqual(meth.elemsz, 12)
        self.assertEqual(meth.valsz, 0)

    def test_memarr_valsz(self):
        meth = addrxlat.MemoryArrayMethod(valsz=8)
        self.assertEqual(meth.kind, addrxlat.MEMARR)
        self.assertEqual(meth.target_as, addrxlat.NOADDR)
        self.assertEqual(meth.base, None)
        self.assertEqual(meth.shift, 0)
        self.assertEqual(meth.elemsz, 0)
        self.assertEqual(meth.valsz, 8)

class TestRange(unittest.TestCase):
    def test_range_defaults(self):
        range = addrxlat.Range()
        self.assertEqual(range.endoff, 0)
        self.assertEqual(range.meth, addrxlat.SYS_METH_NONE)

    def test_range_endoff(self):
        range = addrxlat.Range(endoff=0x1234)
        self.assertEqual(range.endoff, 0x1234)
        self.assertEqual(range.meth, addrxlat.SYS_METH_NONE)

    def test_range_meth(self):
        meth = addrxlat.SYS_METH_PGT
        range = addrxlat.Range(meth=meth)
        self.assertEqual(range.endoff, 0)
        self.assertIs(range.meth, addrxlat.SYS_METH_PGT)

class TestMap(unittest.TestCase):
    def test_map_defaults(self):
        map = addrxlat.Map()
        self.assertEqual(len(map), 0)

    def test_map_set(self):
        map = addrxlat.Map()
        map.set(0, addrxlat.Range(0xffff, addrxlat.SYS_METH_PGT))
        self.assertEqual(len(map), 2)
        self.assertEqual(map[0].endoff, 0xffff)
        self.assertEqual(map[0].meth, addrxlat.SYS_METH_PGT)
        self.assertEqual(map[1].meth, addrxlat.SYS_METH_NONE)

    def test_map_search(self):
        map = addrxlat.Map()
        map.set(0, addrxlat.Range(0xffff, addrxlat.SYS_METH_PGT))
        meth2 = map.search(0)
        self.assertEqual(meth2, addrxlat.SYS_METH_PGT)
        meth2 = map.search(0x10000)
        self.assertIs(meth2, addrxlat.SYS_METH_NONE)

    def test_map_copy(self):
        map = addrxlat.Map()
        map.set(0, addrxlat.Range(0xffff, addrxlat.SYS_METH_PGT))
        self.assertEqual(len(map), 2)
        map2 = map.copy()
        self.assertNotEqual(map2, map)
        self.assertEqual(len(map2), 2)
        self.assertEqual(map2[0].endoff, 0xffff)
        self.assertEqual(map2[0].meth, addrxlat.SYS_METH_PGT)
        self.assertEqual(map2[1].endoff, map[1].endoff)
        self.assertIs(map2[1].meth, addrxlat.SYS_METH_NONE)

class TestSystem(unittest.TestCase):
    def test_sys_defaults(self):
        sys = addrxlat.System()
        for i in xrange(addrxlat.SYS_MAP_NUM):
            map = sys.get_map(i)
            self.assertIs(map, None)
        for i in xrange(addrxlat.SYS_METH_NUM):
            meth = sys.get_meth(i)
            self.assertEqual(meth.kind, addrxlat.NOMETH)

    def test_sys_map(self):
        sys = addrxlat.System()
        newmap = addrxlat.Map()
        for mapidx in xrange(addrxlat.SYS_MAP_NUM):
            sys.set_map(mapidx, newmap)
            for i in xrange(mapidx + 1):
                map = sys.get_map(i)
                self.assertEqual(map, newmap)
            for i in xrange(mapidx + 1, addrxlat.SYS_MAP_NUM):
                map = sys.get_map(i)
                self.assertIs(map, None)
        for i in xrange(addrxlat.SYS_METH_NUM):
            meth = sys.get_meth(i)
            self.assertEqual(meth.kind, addrxlat.NOMETH)

    def test_sys_meth(self):
        sys = addrxlat.System()
        newdesc = addrxlat.LinearMethod(0)
        for i in xrange(addrxlat.SYS_MAP_NUM):
            map = sys.get_map(i)
            self.assertIs(map, None)
        for methidx in xrange(addrxlat.SYS_METH_NUM):
            sys.set_meth(methidx, newdesc)
            for i in xrange(methidx):
                meth = sys.get_meth(i)
                self.assertEqual(meth, newdesc)
            for i in xrange(methidx + 1, addrxlat.SYS_METH_NUM):
                meth = sys.get_meth(i)
                self.assertEqual(meth.kind, addrxlat.NOMETH)

class TestStep(unittest.TestCase):
    def setUp(self):
        self.ctx = addrxlat.Context()

    def test_step_defaults(self):
        step = addrxlat.Step(self.ctx)
        self.assertIs(step.ctx, self.ctx)
        self.assertIs(step.sys, None)
        self.assertIs(step.meth, None)
        self.assertEqual(step.remain, 0)
        self.assertEqual(step.elemsz, 0)
        self.assertIs(step.base, None)
        self.assertIs(step.raw, None)
        idx = (0,) * (addrxlat.FIELDS_MAX + 1)
        self.assertEqual(step.idx, idx)

    def test_step_sys(self):
        sys = addrxlat.System()
        step = addrxlat.Step(self.ctx, sys=sys)
        self.assertIs(step.ctx, self.ctx)
        self.assertIs(step.sys, sys)
        self.assertIs(step.meth, None)
        self.assertEqual(step.remain, 0)
        self.assertEqual(step.elemsz, 0)
        self.assertIs(step.base, None)
        self.assertIs(step.raw, None)
        idx = (0,) * (addrxlat.FIELDS_MAX + 1)
        self.assertEqual(step.idx, idx)

    def test_step_meth(self):
        meth = addrxlat.LinearMethod()
        step = addrxlat.Step(self.ctx, meth=meth)
        self.assertIs(step.ctx, self.ctx)
        self.assertIs(step.sys, None)
        self.assertIs(step.meth, meth)
        self.assertEqual(step.remain, 0)
        self.assertEqual(step.elemsz, 0)
        self.assertIs(step.base, None)
        self.assertIs(step.raw, None)
        idx = (0,) * (addrxlat.FIELDS_MAX + 1)
        self.assertEqual(step.idx, idx)

    def test_step_remain(self):
        step = addrxlat.Step(self.ctx)
        step.remain = 3
        self.assertIs(step.ctx, self.ctx)
        self.assertIs(step.sys, None)
        self.assertIs(step.meth, None)
        self.assertEqual(step.remain, 3)
        self.assertEqual(step.elemsz, 0)
        self.assertIs(step.base, None)
        self.assertIs(step.raw, None)
        idx = (0,) * (addrxlat.FIELDS_MAX + 1)
        self.assertEqual(step.idx, idx)

    def test_step_elemsz(self):
        step = addrxlat.Step(self.ctx)
        step.elemsz = 8
        self.assertIs(step.ctx, self.ctx)
        self.assertIs(step.sys, None)
        self.assertIs(step.meth, None)
        self.assertEqual(step.remain, 0)
        self.assertEqual(step.elemsz, 8)
        self.assertIs(step.base, None)
        self.assertIs(step.raw, None)
        idx = (0,) * (addrxlat.FIELDS_MAX + 1)
        self.assertEqual(step.idx, idx)

    def test_step_base(self):
        step = addrxlat.Step(self.ctx)
        base = addrxlat.FullAddress(addrxlat.KVADDR, 0xabcd)
        step.base = base
        self.assertIs(step.ctx, self.ctx)
        self.assertIs(step.sys, None)
        self.assertIs(step.meth, None)
        self.assertEqual(step.remain, 0)
        self.assertEqual(step.elemsz, 0)
        self.assertIs(step.base, base)
        self.assertIs(step.raw, None)
        idx = (0,) * (addrxlat.FIELDS_MAX + 1)
        self.assertEqual(step.idx, idx)

    def test_step_base_addrspace(self):
        step = addrxlat.Step(self.ctx)
        step.base = addrxlat.FullAddress(addrxlat.NOADDR, 0)
        step.base.addrspace = addrxlat.KVADDR
        self.assertIs(step.ctx, self.ctx)
        self.assertIs(step.sys, None)
        self.assertIs(step.meth, None)
        self.assertEqual(step.remain, 0)
        self.assertEqual(step.elemsz, 0)
        self.assertEqual(step.base, addrxlat.FullAddress(addrxlat.KVADDR, 0))
        self.assertIs(step.raw, None)
        idx = (0,) * (addrxlat.FIELDS_MAX + 1)
        self.assertEqual(step.idx, idx)

    def test_step_base_addr(self):
        step = addrxlat.Step(self.ctx)
        step.base = addrxlat.FullAddress(addrxlat.NOADDR, 0)
        step.base.addr = 0x1234
        self.assertIs(step.ctx, self.ctx)
        self.assertIs(step.sys, None)
        self.assertIs(step.meth, None)
        self.assertEqual(step.remain, 0)
        self.assertEqual(step.elemsz, 0)
        self.assertEqual(step.base, addrxlat.FullAddress(addrxlat.NOADDR, 0x1234))
        self.assertIs(step.raw, None)
        idx = (0,) * (addrxlat.FIELDS_MAX + 1)
        self.assertEqual(step.idx, idx)

    def test_step_raw(self):
        step = addrxlat.Step(self.ctx)
        with self.assertRaisesRegex(TypeError, 'cannot be changed'):
            step.raw = 0xabcd
        meth = addrxlat.PageTableMethod()
        step.meth = meth
        step.raw = 0xabcd
        self.assertIs(step.ctx, self.ctx)
        self.assertIs(step.sys, None)
        self.assertIs(step.meth, meth)
        self.assertEqual(step.remain, 0)
        self.assertEqual(step.elemsz, 0)
        self.assertIs(step.base, None)
        self.assertEqual(step.raw, 0xabcd)
        idx = (0,) * (addrxlat.FIELDS_MAX + 1)
        self.assertEqual(step.idx, idx)

    def test_step_idx(self):
        step = addrxlat.Step(self.ctx)
        idx = (1, 2, 3, 4)
        step.idx = idx
        self.assertIs(step.ctx, self.ctx)
        self.assertIs(step.sys, None)
        self.assertIs(step.meth, None)
        self.assertEqual(step.remain, 0)
        self.assertEqual(step.elemsz, 0)
        self.assertIs(step.base, None)
        self.assertIs(step.raw, None)
        idx = idx + (0,) * (addrxlat.FIELDS_MAX + 1 - len(idx))
        self.assertEqual(step.idx, idx)

        with self.assertRaisesRegex(TypeError, 'not a sequence'):
            step.idx = None
        with self.assertRaisesRegex(ValueError, 'more than [0-9]+ indices'):
            step.idx = (0,) * (addrxlat.FIELDS_MAX + 2)
        with self.assertRaisesRegex(TypeError, 'must be.* a .*number'):
            step.idx = (None,)

class TestOperator(unittest.TestCase):
    def setUp(self):
        self.ctx = addrxlat.Context()

    def test_op_defaults(self):
        op = addrxlat.Operator(self.ctx)
        self.assertIs(op.ctx, self.ctx)
        self.assertIs(op.sys, None)
        self.assertEqual(op.caps, 0)

    def test_op_sys(self):
        sys = addrxlat.System()
        op = addrxlat.Operator(self.ctx, sys=sys)
        self.assertIs(op.ctx, self.ctx)
        self.assertEqual(op.sys, sys)
        self.assertEqual(op.caps, 0)

    def test_op_caps(self):
        op = addrxlat.Operator(self.ctx, caps=addrxlat.CAPS(addrxlat.KVADDR))
        self.assertIs(op.ctx, self.ctx)
        self.assertIs(op.sys, None)
        self.assertEqual(op.caps, addrxlat.CAPS(addrxlat.KVADDR))

#
# Test translation system has the following layout:
#
# MAP_HW:
# 0-ffff: PGT root=MACHPHYSADDR:0
# 10000-ffffffffffffffff: NONE
#
# MAP_KV_PHYS:
# 0-1fff: DIRECT off=0x1000
# 2000-3fff: LOOKUP
# 4000-5fff: MEMARR base=KVADDR:0
# 6000-ffff: PGT
# 10000-ffffffffffffffff: NONE
#
# MAP_KPHYS_DIRECT:
# 0-fff: NONE
# 1000-2fff: RDIRECT
# 3000-ffffffffffffffff: NONE
#
# MAP_MACHPHYS_KPHYS:
# 0-ffff: NONE
# 10000-1ffff: KPHYS_MACHPHYS
# 20000-ffffffffffffffff: NONE
#
# MAP_KPHYS_MACHPHYS:
# 0-ffff: MACHPHYS_KPHYS
# 10000-ffffffffffffffff: NONE
#
class TestTranslation(unittest.TestCase):
    def setUp(self):
        def get_page(addr):
            # Page table level 2 @ 0
            if addr.addr == 0x10000:
                return (bytearray((0x00, 0x00, 0x01, 0x01)),
                        addrxlat.BIG_ENDIAN)
            # Page table level 1 @ 0x65
            if addr.addr == 0x10100 + 0x65 * 4:
                return (bytearray((0x00, 0x00, 0x01, 0xc0)),
                        addrxlat.BIG_ENDIAN)
            # Page table level 1 @ 0x41
            if addr.addr == 0x10100 + 0x41 * 4:
                return (bytearray((0x00, 0x00, 0x01, 0xa9)),
                        addrxlat.BIG_ENDIAN)
            # Memory array at 0x40
            if addr.addr == 0x11000 + 0x40 * 4:
                return (bytearray((0x00, 0x00, 0x00, 0xaa)),
                        addrxlat.BIG_ENDIAN)

        def read_caps():
            return addrxlat.CAPS(addrxlat.MACHPHYSADDR)

        self.ctx = addrxlat.Context()
        self.ctx.cb_read_caps = read_caps
        self.ctx.cb_get_page = get_page
        self.sys = addrxlat.System()

        map = addrxlat.Map()
        self.sys.set_map(addrxlat.SYS_MAP_HW, map)
        meth = addrxlat.PageTableMethod(addrxlat.MACHPHYSADDR)
        meth.root = addrxlat.FullAddress(addrxlat.MACHPHYSADDR, 0x10000)
        meth.pte_format = addrxlat.PTE_PFN32
        meth.fields = (8, 8, 8)
        self.sys.set_meth(addrxlat.SYS_METH_PGT, meth)
        map.set(0, addrxlat.Range(0xffff, addrxlat.SYS_METH_PGT))

        map = addrxlat.Map()
        self.sys.set_map(addrxlat.SYS_MAP_KV_PHYS, map)
        meth = addrxlat.LinearMethod(addrxlat.KPHYSADDR, 0x1000)
        self.sys.set_meth(addrxlat.SYS_METH_DIRECT, meth)
        map.set(0, addrxlat.Range(0x1fff, addrxlat.SYS_METH_DIRECT))
        meth = addrxlat.LookupMethod(addrxlat.KPHYSADDR)
        meth.endoff = 0xff
        meth.tbl = ((0x2000, 0xfa00), (0x3000, 0xfb00), (0x3100, 0xff00))
        self.sys.set_meth(addrxlat.SYS_METH_CUSTOM, meth)
        map.set(0x2000, addrxlat.Range(0x1fff, addrxlat.SYS_METH_CUSTOM))
        meth = addrxlat.MemoryArrayMethod(addrxlat.KPHYSADDR)
        meth.base = addrxlat.FullAddress(addrxlat.KVADDR, 0)
        meth.shift = 8
        meth.elemsz = 4
        meth.valsz = 4
        self.sys.set_meth(addrxlat.SYS_METH_CUSTOM + 1, meth)
        map.set(0x4000, addrxlat.Range(0x1fff, addrxlat.SYS_METH_CUSTOM + 1))
        map.set(0x6000, addrxlat.Range(0x9fff, addrxlat.SYS_METH_PGT))

        map = addrxlat.Map()
        self.sys.set_map(addrxlat.SYS_MAP_KPHYS_DIRECT, map)
        meth = addrxlat.LinearMethod(addrxlat.KVADDR, -0x1000)
        self.sys.set_meth(addrxlat.SYS_METH_RDIRECT, meth)
        map.set(0x1000, addrxlat.Range(0x1fff, addrxlat.SYS_METH_RDIRECT))

        map = addrxlat.Map()
        self.sys.set_map(addrxlat.SYS_MAP_MACHPHYS_KPHYS, map)
        meth = addrxlat.LinearMethod(addrxlat.KPHYSADDR, -0x10000)
        self.sys.set_meth(addrxlat.SYS_METH_MACHPHYS_KPHYS, meth)
        map.set(0x10000, addrxlat.Range(0xffff, addrxlat.SYS_METH_MACHPHYS_KPHYS))

        map = addrxlat.Map()
        self.sys.set_map(addrxlat.SYS_MAP_KPHYS_MACHPHYS, map)
        meth = addrxlat.LinearMethod(addrxlat.MACHPHYSADDR, 0x10000)
        self.sys.set_meth(addrxlat.SYS_METH_KPHYS_MACHPHYS, meth)
        map.set(0, addrxlat.Range(0xffff, addrxlat.SYS_METH_KPHYS_MACHPHYS))

    def test_fulladdr_conv_kphys_machphys(self):
        "KPHYS -> MACHPHYS using offset"
        addr = addrxlat.FullAddress(addrxlat.KPHYSADDR, 0x2345)
        addr.conv(addrxlat.MACHPHYSADDR, self.ctx, self.sys)
        self.assertEqual(addr, addrxlat.FullAddress(addrxlat.MACHPHYSADDR, 0x12345))

    def test_fulladdr_fail_kphys_machphys(self):
        "KPHYS -> MACHPHYS out of bounds"
        addr = addrxlat.FullAddress(addrxlat.KPHYSADDR, 0xf4255)
        with self.assertRaisesRegex(addrxlat.NoMethodError, 'No way to translate'):
            addr.conv(addrxlat.MACHPHYSADDR, self.ctx, self.sys)

    def test_fulladdr_conv_machphys_kphys(self):
        "MACHPHYS -> KPHYS using offset"
        addr = addrxlat.FullAddress(addrxlat.MACHPHYSADDR, 0x1abcd)
        addr.conv(addrxlat.KPHYSADDR, self.ctx, self.sys)
        self.assertEqual(addr, addrxlat.FullAddress(addrxlat.KPHYSADDR, 0xabcd))

    def test_fulladdr_fail_machphys_kphys(self):
        "MACHPHYS -> KPHYS out of bounds"
        addr = addrxlat.FullAddress(addrxlat.MACHPHYSADDR, 0xabcd)
        with self.assertRaisesRegex(addrxlat.NoMethodError, 'No way to translate'):
            addr.conv(addrxlat.KPHYSADDR, self.ctx, self.sys)

    def test_fulladdr_conv_direct(self):
        "KV -> KPHYS using directmap"
        addr = addrxlat.FullAddress(addrxlat.KVADDR, 0x1234)
        addr.conv(addrxlat.KPHYSADDR, self.ctx, self.sys)
        self.assertEqual(addr, addrxlat.FullAddress(addrxlat.KPHYSADDR, 0x2234))

    def test_fulladdr_conv_lookup(self):
        "KV -> KPHYS using lookup"
        addr = addrxlat.FullAddress(addrxlat.KVADDR, 0x2055)
        addr.conv(addrxlat.KPHYSADDR, self.ctx, self.sys)
        self.assertEqual(addr, addrxlat.FullAddress(addrxlat.KPHYSADDR, 0xfa55))

    def test_fulladdr_conv_memarr(self):
        "KV -> KPHYS using memory array"
        addr = addrxlat.FullAddress(addrxlat.KVADDR, 0x4055)
        addr.conv(addrxlat.KPHYSADDR, self.ctx, self.sys)
        self.assertEqual(addr, addrxlat.FullAddress(addrxlat.KPHYSADDR, 0xaa55))

    def test_fulladdr_conv_memarr_pgt(self):
        "KV -> KPHYS using fallback from memory array to page tables"
        addr = addrxlat.FullAddress(addrxlat.KVADDR, 0x4155)
        addr.conv(addrxlat.KPHYSADDR, self.ctx, self.sys)
        self.assertEqual(addr, addrxlat.FullAddress(addrxlat.KPHYSADDR, 0xa955))

    def test_fulladdr_fail_memarr(self):
        "KV -> KPHYS using memory array returns None"
        addr = addrxlat.FullAddress(addrxlat.KVADDR, 0x4255)
        with self.assertRaisesRegex(addrxlat.NoMethodError, 'Callback returned None'):
            addr.conv(addrxlat.KPHYSADDR, self.ctx, self.sys)

    def test_fulladdr_conv_pgt(self):
        "KV -> KPHYS using page tables"
        addr = addrxlat.FullAddress(addrxlat.KVADDR, 0x6502)
        addr.conv(addrxlat.KPHYSADDR, self.ctx, self.sys)
        self.assertEqual(addr, addrxlat.FullAddress(addrxlat.KPHYSADDR, 0xc002))

    def test_fulladdr_conv_rdirect(self):
        "KPHYS -> KV using reverse directmap"
        addr = addrxlat.FullAddress(addrxlat.KPHYSADDR, 0x2345)
        addr.conv(addrxlat.KVADDR, self.ctx, self.sys)
        self.assertEqual(addr, addrxlat.FullAddress(addrxlat.KVADDR, 0x1345))

    def test_op_direct(self):
        "Operator using directmap"
        class hexop(addrxlat.Operator):
            def __init__(self, prefix='', *args, **kwargs):
                super(hexop, self).__init__(*args, **kwargs)
                self.prefix = prefix

            def callback(self, addr):
                return '{}{:x}'.format(self.prefix, addr.addr)

        myop = hexop(ctx=self.ctx, sys=self.sys, caps=addrxlat.CAPS(addrxlat.KPHYSADDR), prefix='0x')
        result = myop(addrxlat.FullAddress(addrxlat.KVADDR, 0xabc))
        self.assertEqual(result, '0x1abc')

    def test_subclass_memarr(self):
        "KV -> KPHYS using memory array and a subclass"

        class mycontext(addrxlat.Context):
            def __init__(self, *args, **kwargs):
                super(mycontext, self).__init__(*args, **kwargs)
            def cb_read_caps(self):
                return addrxlat.CAPS(addrxlat.MACHPHYSADDR)
            def cb_get_page(self, addr):
                # Memory array at 0x40
                if addr.addr == 0x11000 + 0x40 * 4:
                    return (bytearray((0x00, 0x00, 0x00, 0x12)),
                            addrxlat.BIG_ENDIAN)

        ctx = mycontext()
        addr = addrxlat.FullAddress(addrxlat.KVADDR, 0x4034)
        addr.conv(addrxlat.KPHYSADDR, ctx, self.sys)
        self.assertEqual(addr, addrxlat.FullAddress(addrxlat.KPHYSADDR, 0x1234))

class TestCustom(unittest.TestCase):
    def setUp(self):
        self.ctx = addrxlat.Context()

        def first_step(step, addr):
            step.base = addrxlat.FullAddress(addrxlat.NOADDR, 0xabcdef)
            step.idx = (addr & 0xff, addr >> 8)
            step.remain = 2

        def next_step(step):
            step.base.addr = 0x123456 + step.idx[1]
            step.elemsz = 0x100

        self.meth = addrxlat.CustomMethod()
        self.meth.target_as = addrxlat.KPHYSADDR
        self.meth.cb_first_step = first_step
        self.meth.cb_next_step = next_step

        import _test_addrxlat
        self.meth_ext = _test_addrxlat.getCustomMethod(addrxlat.convert)
        self.assertEqual(self.meth_ext.kind, addrxlat.CUSTOM)
        self.assertEqual(self.meth_ext.target_as, addrxlat.NOADDR)
        self.meth_ext.target_as = addrxlat.KPHYSADDR

        self.meth_extmod = _test_addrxlat.getCustomMethod(addrxlat.convert)
        self.meth_extmod.target_as = addrxlat.KPHYSADDR
        self.meth_extmod.cb_next_step = next_step

    def test_customdesc_cb(self):
        step = addrxlat.Step(ctx=self.ctx, meth=self.meth)
        self.assertIs(step.base, None)
        self.meth.cb_first_step(step, 0x1234)
        self.assertEqual(step.base.addrspace, addrxlat.NOADDR)
        self.assertEqual(step.base.addr, 0xabcdef)
        self.assertEqual(step.idx[0], 0x34)
        self.assertEqual(step.idx[1], 0x12)
        self.meth.cb_next_step(step)
        self.assertEqual(step.base.addrspace, addrxlat.NOADDR)
        self.assertEqual(step.base.addr, 0x123456 + 0x12)
        self.assertEqual(step.idx[0], 0x34)
        self.assertEqual(step.idx[1], 0x12)

    def test_customdesc_conv(self):
        sys = addrxlat.System()
        map = addrxlat.Map()
        sys.set_meth(addrxlat.SYS_METH_CUSTOM, self.meth)
        map.set(0, addrxlat.Range(0xffff, addrxlat.SYS_METH_CUSTOM))
        sys.set_map(addrxlat.SYS_MAP_KV_PHYS, map)
        addr = addrxlat.FullAddress(addrxlat.KVADDR, 0x2345)
        addr.conv(addrxlat.KPHYSADDR, self.ctx, sys)
        self.assertEqual(addr.addrspace, addrxlat.KPHYSADDR)
        self.assertEqual(addr.addr, 0x123456 + 0x4523)

    def test_customdesc_ext_cb(self):
        step = addrxlat.Step(ctx=self.ctx, meth=self.meth_ext)
        self.assertIs(step.base, None)
        self.meth_ext.cb_first_step(step, 0x1234)
        self.assertEqual(step.base.addrspace, addrxlat.NOADDR)
        self.assertEqual(step.base.addr, 0x4d795f4d61676963)
        self.assertEqual(step.idx[0], 0x34)
        self.assertEqual(step.idx[1], 0x12)
        self.meth_ext.cb_next_step(step)
        self.assertEqual(step.base.addrspace, addrxlat.NOADDR)
        self.assertEqual(step.base.addr, 0x4d61676963546f6f + 0x12)
        self.assertEqual(step.idx[0], 0x34)
        self.assertEqual(step.idx[1], 0x12)

    def test_customdesc_ext_conv(self):
        sys = addrxlat.System()
        map = addrxlat.Map()
        sys.set_meth(addrxlat.SYS_METH_CUSTOM, self.meth_ext)
        map.set(0, addrxlat.Range(0xffff, addrxlat.SYS_METH_CUSTOM))
        sys.set_map(addrxlat.SYS_MAP_KV_PHYS, map)
        addr = addrxlat.FullAddress(addrxlat.KVADDR, 0x2345)
        addr.conv(addrxlat.KPHYSADDR, self.ctx, sys)
        self.assertEqual(addr.addrspace, addrxlat.KPHYSADDR)
        self.assertEqual(addr.addr, 0x4d61676963546f6f + 0x4523)

    def test_customdesc_extmod_cb(self):
        step = addrxlat.Step(ctx=self.ctx, meth=self.meth_extmod)
        self.assertIs(step.base, None)
        self.meth_extmod.cb_first_step(step, 0x1234)
        self.assertEqual(step.base.addrspace, addrxlat.NOADDR)
        self.assertEqual(step.base.addr, 0x4d795f4d61676963)
        self.assertEqual(step.idx[0], 0x34)
        self.assertEqual(step.idx[1], 0x12)
        self.meth_extmod.cb_next_step(step)
        self.assertEqual(step.base.addrspace, addrxlat.NOADDR)
        self.assertEqual(step.base.addr, 0x123456 + 0x12)
        self.assertEqual(step.idx[0], 0x34)
        self.assertEqual(step.idx[1], 0x12)

    def test_customdesc_extmod_conv(self):
        sys = addrxlat.System()
        map = addrxlat.Map()
        sys.set_meth(addrxlat.SYS_METH_CUSTOM, self.meth_extmod)
        map.set(0, addrxlat.Range(0xffff, addrxlat.SYS_METH_CUSTOM))
        sys.set_map(addrxlat.SYS_MAP_KV_PHYS, map)
        addr = addrxlat.FullAddress(addrxlat.KVADDR, 0x2345)
        addr.conv(addrxlat.KPHYSADDR, self.ctx, sys)
        self.assertEqual(addr.addrspace, addrxlat.KPHYSADDR)
        self.assertEqual(addr.addr, 0x123456 + 0x4523)

if __name__ == '__main__':
    unittest.main()
