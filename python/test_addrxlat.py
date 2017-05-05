#!/usr/bin/env python
# vim:sw=4 ts=4 et

import unittest
import addrxlat

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

class TestDescription(unittest.TestCase):
    def test_desc_defaults(self):
        desc = addrxlat.Description(addrxlat.NOMETH)
        self.assertEqual(desc.kind, addrxlat.NOMETH)
        self.assertEqual(desc.target_as, addrxlat.NOADDR)
        for i in xrange(len(desc.param)):
            self.assertEqual(desc.param[i], 0)

    def test_desc_readonly_kind(self):
        desc = addrxlat.Description(addrxlat.NOMETH)
        with self.assertRaises(AttributeError):
            desc.kind = addrxlat.LINEAR

    def test_desc_target_as(self):
        desc = addrxlat.Description(addrxlat.NOMETH, addrxlat.MACHPHYSADDR)
        self.assertEqual(desc.kind, addrxlat.NOMETH)
        self.assertEqual(desc.target_as, addrxlat.MACHPHYSADDR)
        for i in xrange(len(desc.param)):
            self.assertEqual(desc.param[i], 0)

    def test_desc_param(self):
        desc = addrxlat.Description(addrxlat.NOMETH, param=(0, 1, 2, 3))
        self.assertGreaterEqual(len(desc.param), 4)
        self.assertEqual(desc.kind, addrxlat.NOMETH)
        self.assertEqual(desc.target_as, addrxlat.NOADDR)
        for i in xrange(4):
            self.assertEqual(desc.param[i], i)
        for i in xrange(4, len(desc.param)):
            self.assertEqual(desc.param[i], 0)

        for i in xrange(4):
            desc.param[i] += 1
        self.assertEqual(desc.kind, addrxlat.NOMETH)
        self.assertEqual(desc.target_as, addrxlat.NOADDR)
        for i in xrange(4):
            self.assertEqual(desc.param[i], i + 1)
        for i in xrange(4, len(desc.param)):
            self.assertEqual(desc.param[i], 0)

        with self.assertRaises(OverflowError):
            desc.param[0] = 999
        with self.assertRaises(OverflowError):
            desc.param[0] = -1

    def test_custom_defaults(self):
        desc = addrxlat.CustomDescription()
        self.assertEqual(desc.kind, addrxlat.CUSTOM)
        self.assertEqual(desc.target_as, addrxlat.NOADDR)

    def test_custom_readonly_kind(self):
        desc = addrxlat.CustomDescription()
        with self.assertRaises(AttributeError):
            desc.kind = addrxlat.NOMETH

    def test_custom_target_as(self):
        desc = addrxlat.CustomDescription(addrxlat.MACHPHYSADDR)
        self.assertEqual(desc.kind, addrxlat.CUSTOM)
        self.assertEqual(desc.target_as, addrxlat.MACHPHYSADDR)

    def test_custom_notimpl(self):
        desc = addrxlat.CustomDescription(addrxlat.MACHPHYSADDR)
        self.assertEqual(desc.kind, addrxlat.CUSTOM)
        self.assertEqual(desc.target_as, addrxlat.MACHPHYSADDR)
        ctx = addrxlat.Context()
        meth = addrxlat.Method(desc)
        step = addrxlat.Step(ctx=ctx, meth=meth)
        with self.assertRaisesRegexp(BaseException, "NULL callback"):
            desc.cb_first_step(step, 0x1234)
        with self.assertRaisesRegexp(BaseException, "NULL callback"):
            desc.cb_next_step(step)

    def test_linear_defaults(self):
        desc = addrxlat.LinearDescription()
        self.assertEqual(desc.kind, addrxlat.LINEAR)
        self.assertEqual(desc.target_as, addrxlat.NOADDR)
        self.assertEqual(desc.off, 0)

    def test_linear_readonly_kind(self):
        desc = addrxlat.LinearDescription()
        with self.assertRaises(AttributeError):
            desc.kind = addrxlat.NOMETH

    def test_linear_target_as(self):
        desc = addrxlat.LinearDescription(addrxlat.MACHPHYSADDR)
        self.assertEqual(desc.kind, addrxlat.LINEAR)
        self.assertEqual(desc.target_as, addrxlat.MACHPHYSADDR)
        self.assertEqual(desc.off, 0)

    def test_linear_off(self):
        desc = addrxlat.LinearDescription(off=addrxlat.ADDR_MAX - 0x1234)
        self.assertEqual(desc.kind, addrxlat.LINEAR)
        self.assertEqual(desc.target_as, addrxlat.NOADDR)
        self.assertEqual(desc.off, addrxlat.ADDR_MAX - 0x1234)

    def test_linear_neg_off(self):
        desc = addrxlat.LinearDescription(off=-addrxlat.ADDR_MAX)
        self.assertEqual(desc.kind, addrxlat.LINEAR)
        self.assertEqual(desc.target_as, addrxlat.NOADDR)
        self.assertEqual(desc.off, 1)

    def test_linear_param(self):
        desc = addrxlat.LinearDescription(off=0x1234)
        param = tuple(desc.param)
        self.assertLess(param.index(0x34), len(desc.param))
        desc.param = (0xff,) * len(desc.param)
        self.assertNotEqual(desc.off, 0x1234)

    def test_pgt_defaults(self):
        desc = addrxlat.PageTableDescription()
        self.assertEqual(desc.kind, addrxlat.PGT)
        self.assertEqual(desc.target_as, addrxlat.NOADDR)
        self.assertIs(desc.root, None)
        self.assertEqual(desc.pte_format, addrxlat.PTE_NONE)
        self.assertEqual(desc.fields, tuple())

    def test_pgt_readonly_kind(self):
        desc = addrxlat.PageTableDescription()
        with self.assertRaises(AttributeError):
            desc.kind = addrxlat.NOMETH

    def test_pgt_target_as(self):
        desc = addrxlat.PageTableDescription(addrxlat.MACHPHYSADDR)
        self.assertEqual(desc.kind, addrxlat.PGT)
        self.assertEqual(desc.target_as, addrxlat.MACHPHYSADDR)
        self.assertIs(desc.root, None)
        self.assertEqual(desc.pte_format, addrxlat.PTE_NONE)
        self.assertEqual(desc.fields, tuple())

    def test_pgt_root(self):
        root = addrxlat.FullAddress(addrxlat.MACHPHYSADDR, 0x1000)
        desc = addrxlat.PageTableDescription(root=root)
        self.assertEqual(desc.kind, addrxlat.PGT)
        self.assertEqual(desc.target_as, addrxlat.NOADDR)
        self.assertEqual(desc.root, root)
        self.assertEqual(desc.pte_format, addrxlat.PTE_NONE)
        self.assertEqual(desc.fields, tuple())

    def test_pgt_pte_format(self):
        desc = addrxlat.PageTableDescription(pte_format=addrxlat.PTE_PFN32)
        self.assertEqual(desc.kind, addrxlat.PGT)
        self.assertEqual(desc.target_as, addrxlat.NOADDR)
        self.assertIs(desc.root, None)
        self.assertEqual(desc.pte_format, addrxlat.PTE_PFN32)
        self.assertEqual(desc.fields, tuple())

    def test_pgt_fields(self):
        desc = addrxlat.PageTableDescription(fields=(1, 2, 3))
        self.assertEqual(desc.kind, addrxlat.PGT)
        self.assertEqual(desc.target_as, addrxlat.NOADDR)
        self.assertIs(desc.root, None)
        self.assertEqual(desc.pte_format, addrxlat.PTE_NONE)
        self.assertEqual(desc.fields, (1, 2, 3))

        desc.fields = (4, 5, 6)
        self.assertEqual(desc.fields, (4, 5, 6))
        with self.assertRaisesRegexp(TypeError, 'not a sequence'):
            desc.fields = None
        with self.assertRaisesRegexp(ValueError,
                                     'more than [0-9]+ address fields'):
            desc.fields = (0,) * (addrxlat.FIELDS_MAX + 1)

    def test_lookup_defaults(self):
        desc = addrxlat.LookupDescription()
        self.assertEqual(desc.kind, addrxlat.LOOKUP)
        self.assertEqual(desc.target_as, addrxlat.NOADDR)
        self.assertEqual(desc.endoff, 0)
        self.assertEqual(desc.tbl, tuple())

    def test_lookup_readonly_kind(self):
        desc = addrxlat.LookupDescription()
        with self.assertRaises(AttributeError):
            desc.kind = addrxlat.NOMETH

    def test_lookup_target_as(self):
        desc = addrxlat.LookupDescription(addrxlat.MACHPHYSADDR)
        self.assertEqual(desc.kind, addrxlat.LOOKUP)
        self.assertEqual(desc.target_as, addrxlat.MACHPHYSADDR)
        self.assertEqual(desc.endoff, 0)
        self.assertEqual(desc.tbl, tuple())

    def test_lookup_endoff(self):
        desc = addrxlat.LookupDescription(endoff=0x1234)
        self.assertEqual(desc.kind, addrxlat.LOOKUP)
        self.assertEqual(desc.target_as, addrxlat.NOADDR)
        self.assertEqual(desc.endoff, 0x1234)
        self.assertEqual(desc.tbl, tuple())

    def test_lookup_tbl(self):
        desc = addrxlat.LookupDescription(tbl=((0, 100), (200, 300)))
        self.assertEqual(desc.kind, addrxlat.LOOKUP)
        self.assertEqual(desc.target_as, addrxlat.NOADDR)
        self.assertEqual(desc.endoff, 0)
        self.assertEqual(desc.tbl, ((0, 100), (200, 300)))

        with self.assertRaisesRegexp(TypeError, 'not a sequence'):
            desc.tbl = None
        with self.assertRaisesRegexp(TypeError, 'not a sequence'):
            desc.tbl = (None,)
        with self.assertRaisesRegexp(TypeError, 'not a sequence'):
            desc.tbl = 1
        with self.assertRaisesRegexp(TypeError, 'not a sequence'):
            desc.tbl = (1,)
        with self.assertRaisesRegexp(ValueError, 'must be integer pairs'):
            desc.tbl = ((),)
        with self.assertRaisesRegexp(ValueError, 'must be integer pairs'):
            desc.tbl = ((1,),)
        with self.assertRaisesRegexp(ValueError, 'must be integer pairs'):
            desc.tbl = ((1, 2, 3),)
        with self.assertRaisesRegexp(TypeError, 'not an integer'):
            desc.tbl = ((None, None),)
        with self.assertRaisesRegexp(TypeError, 'not an integer'):
            desc.tbl = ((1, None),)
        with self.assertRaisesRegexp(TypeError, 'not an integer'):
            desc.tbl = ((None, 1),)

    def test_memarr_defaults(self):
        desc = addrxlat.MemoryArrayDescription()
        self.assertEqual(desc.kind, addrxlat.MEMARR)
        self.assertEqual(desc.target_as, addrxlat.NOADDR)
        self.assertEqual(desc.base, None)
        self.assertEqual(desc.shift, 0)
        self.assertEqual(desc.elemsz, 0)
        self.assertEqual(desc.valsz, 0)

    def test_memarr_readonly_kind(self):
        desc = addrxlat.MemoryArrayDescription()
        with self.assertRaises(AttributeError):
            desc.kind = addrxlat.NOMETH

    def test_memarr_target_as(self):
        desc = addrxlat.MemoryArrayDescription(addrxlat.MACHPHYSADDR)
        self.assertEqual(desc.kind, addrxlat.MEMARR)
        self.assertEqual(desc.target_as, addrxlat.MACHPHYSADDR)
        self.assertEqual(desc.base, None)
        self.assertEqual(desc.shift, 0)
        self.assertEqual(desc.elemsz, 0)
        self.assertEqual(desc.valsz, 0)

    def test_memarr_base(self):
        base = addrxlat.FullAddress(addrxlat.MACHPHYSADDR, 0x1234)
        desc = addrxlat.MemoryArrayDescription(base=base)
        self.assertEqual(desc.kind, addrxlat.MEMARR)
        self.assertEqual(desc.target_as, addrxlat.NOADDR)
        self.assertEqual(desc.base, base)
        self.assertEqual(desc.shift, 0)
        self.assertEqual(desc.elemsz, 0)
        self.assertEqual(desc.valsz, 0)

    def test_memarr_shift(self):
        desc = addrxlat.MemoryArrayDescription(shift=3)
        self.assertEqual(desc.kind, addrxlat.MEMARR)
        self.assertEqual(desc.target_as, addrxlat.NOADDR)
        self.assertEqual(desc.base, None)
        self.assertEqual(desc.shift, 3)
        self.assertEqual(desc.elemsz, 0)
        self.assertEqual(desc.valsz, 0)

    def test_memarr_elemsz(self):
        desc = addrxlat.MemoryArrayDescription(elemsz=12)
        self.assertEqual(desc.kind, addrxlat.MEMARR)
        self.assertEqual(desc.target_as, addrxlat.NOADDR)
        self.assertEqual(desc.base, None)
        self.assertEqual(desc.shift, 0)
        self.assertEqual(desc.elemsz, 12)
        self.assertEqual(desc.valsz, 0)

    def test_memarr_valsz(self):
        desc = addrxlat.MemoryArrayDescription(valsz=8)
        self.assertEqual(desc.kind, addrxlat.MEMARR)
        self.assertEqual(desc.target_as, addrxlat.NOADDR)
        self.assertEqual(desc.base, None)
        self.assertEqual(desc.shift, 0)
        self.assertEqual(desc.elemsz, 0)
        self.assertEqual(desc.valsz, 8)

class TestMethod(unittest.TestCase):
    def test_method_defaults(self):
        meth = addrxlat.Method()
        desc = meth.get_desc()
        self.assertEqual(desc.kind, 0)
        self.assertEqual(desc.target_as, 0)
        for i in xrange(len(desc.param)):
            self.assertEqual(desc.param[i], 0)

    def test_method_set(self):
        desc = addrxlat.LinearDescription(addrxlat.MACHPHYSADDR, 0x1234)
        meth = addrxlat.Method(desc)
        desc2 = meth.get_desc()
        self.assertEqual(desc2.kind, addrxlat.LINEAR)
        self.assertEqual(desc2.target_as, addrxlat.MACHPHYSADDR)
        self.assertEqual(desc2.off, 0x1234)

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

    def test_map_clear(self):
        map = addrxlat.Map()
        map.set(0, addrxlat.Range(0xffff, addrxlat.SYS_METH_PGT))
        self.assertEqual(len(map), 2)
        map.clear()
        self.assertEqual(len(map), 0)

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
            self.assertIs(meth, None)

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
            self.assertIs(meth, None)

    def test_sys_meth(self):
        sys = addrxlat.System()
        newmeth = addrxlat.Method()
        for i in xrange(addrxlat.SYS_MAP_NUM):
            map = sys.get_map(i)
            self.assertIs(map, None)
        for methidx in xrange(addrxlat.SYS_METH_NUM):
            sys.set_meth(methidx, newmeth)
            for i in xrange(methidx):
                meth = sys.get_meth(i)
                self.assertEqual(meth, newmeth)
            for i in xrange(methidx + 1, addrxlat.SYS_METH_NUM):
                meth = sys.get_meth(i)
                self.assertIs(meth, None)

class TestStep(unittest.TestCase):
    def setUp(self):
        self.ctx = addrxlat.Context()

    def test_step_defaults(self):
        step = addrxlat.Step(self.ctx)
        self.assertIs(step.ctx, self.ctx)
        self.assertIs(step.sys, None)
        self.assertIs(step.desc, None)
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
        self.assertEqual(step.sys, sys)
        self.assertIs(step.desc, None)
        self.assertEqual(step.remain, 0)
        self.assertEqual(step.elemsz, 0)
        self.assertIs(step.base, None)
        self.assertIs(step.raw, None)
        idx = (0,) * (addrxlat.FIELDS_MAX + 1)
        self.assertEqual(step.idx, idx)

    def test_step_desc(self):
        desc = addrxlat.LinearDescription()
        step = addrxlat.Step(self.ctx, desc=desc)
        self.assertIs(step.ctx, self.ctx)
        self.assertIs(step.sys, None)
        self.assertEqual(step.desc, desc)
        self.assertEqual(step.remain, 0)
        self.assertEqual(step.elemsz, 0)
        self.assertIs(step.base, None)
        self.assertIs(step.raw, None)
        idx = (0,) * (addrxlat.FIELDS_MAX + 1)
        self.assertEqual(step.idx, idx)

    def test_step_remain(self):
        sys = addrxlat.System()
        step = addrxlat.Step(self.ctx, sys=sys)
        step.remain = 3
        self.assertIs(step.ctx, self.ctx)
        self.assertEqual(step.sys, sys)
        self.assertIs(step.desc, None)
        self.assertEqual(step.remain, 3)
        self.assertEqual(step.elemsz, 0)
        self.assertIs(step.base, None)
        self.assertIs(step.raw, None)
        idx = (0,) * (addrxlat.FIELDS_MAX + 1)
        self.assertEqual(step.idx, idx)

    def test_step_elemsz(self):
        sys = addrxlat.System()
        step = addrxlat.Step(self.ctx, sys=sys)
        step.elemsz = 8
        self.assertIs(step.ctx, self.ctx)
        self.assertEqual(step.sys, sys)
        self.assertIs(step.desc, None)
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
        self.assertIs(step.desc, None)
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
        self.assertIs(step.desc, None)
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
        self.assertIs(step.desc, None)
        self.assertEqual(step.remain, 0)
        self.assertEqual(step.elemsz, 0)
        self.assertEqual(step.base, addrxlat.FullAddress(addrxlat.NOADDR, 0x1234))
        self.assertIs(step.raw, None)
        idx = (0,) * (addrxlat.FIELDS_MAX + 1)
        self.assertEqual(step.idx, idx)

    def test_step_raw(self):
        step = addrxlat.Step(self.ctx)
        with self.assertRaisesRegexp(TypeError, 'cannot be changed'):
            step.raw = 0xabcd
        desc = addrxlat.PageTableDescription()
        step.desc = desc
        step.raw = 0xabcd
        self.assertIs(step.ctx, self.ctx)
        self.assertIs(step.sys, None)
        self.assertEqual(step.desc, desc)
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
        self.assertIs(step.desc, None)
        self.assertEqual(step.remain, 0)
        self.assertEqual(step.elemsz, 0)
        self.assertIs(step.base, None)
        self.assertIs(step.raw, None)
        idx = idx + (0,) * (addrxlat.FIELDS_MAX + 1 - len(idx))
        self.assertEqual(step.idx, idx)

        with self.assertRaisesRegexp(TypeError, 'not a sequence'):
            step.idx = None
        with self.assertRaisesRegexp(ValueError, 'more than [0-9]+ indices'):
            step.idx = (0,) * (addrxlat.FIELDS_MAX + 2)
        with self.assertRaisesRegexp(TypeError, 'not an integer'):
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
        def read32(addr):
            # Page table level 2 @ 0
            if addr.addr == 0x10000:
                return 0x101
            # Page table level 1 @ 0x65
            if addr.addr == 0x10100 + 0x65 * 4:
                return 0x1c0
            # Page table level 1 @ 0x41
            if addr.addr == 0x10100 + 0x41 * 4:
                return 0x1a9
            # Memory array at 0x40
            if addr.addr == 0x11000 + 0x40 * 4:
                return 0xaa

        self.ctx = addrxlat.Context()
        self.ctx.read_caps = addrxlat.CAPS(addrxlat.MACHPHYSADDR)
        self.ctx.cb_read32 = read32
        self.sys = addrxlat.System()

        map = addrxlat.Map()
        self.sys.set_map(addrxlat.SYS_MAP_HW, map)
        desc = addrxlat.PageTableDescription(addrxlat.MACHPHYSADDR)
        desc.root = addrxlat.FullAddress(addrxlat.MACHPHYSADDR, 0x10000)
        desc.pte_format = addrxlat.PTE_PFN32
        desc.fields = (8, 8, 8)
        pgtmeth = addrxlat.Method(desc)
        self.sys.set_meth(addrxlat.SYS_METH_PGT, pgtmeth)
        map.set(0, addrxlat.Range(0xffff, addrxlat.SYS_METH_PGT))

        map = addrxlat.Map()
        self.sys.set_map(addrxlat.SYS_MAP_KV_PHYS, map)
        desc = addrxlat.LinearDescription(addrxlat.KPHYSADDR, 0x1000)
        meth = addrxlat.Method(desc)
        self.sys.set_meth(addrxlat.SYS_METH_DIRECT, meth)
        map.set(0, addrxlat.Range(0x1fff, addrxlat.SYS_METH_DIRECT))
        desc = addrxlat.LookupDescription(addrxlat.KPHYSADDR)
        desc.endoff = 0xff
        desc.tbl = ((0x2000, 0xfa00), (0x3000, 0xfb00), (0x3100, 0xff00))
        meth = addrxlat.Method(desc)
        self.sys.set_meth(addrxlat.SYS_METH_CUSTOM, meth)
        map.set(0x2000, addrxlat.Range(0x1fff, addrxlat.SYS_METH_CUSTOM))
        desc = addrxlat.MemoryArrayDescription(addrxlat.KPHYSADDR)
        desc.base = addrxlat.FullAddress(addrxlat.KVADDR, 0)
        desc.shift = 8
        desc.elemsz = 4
        desc.valsz = 4
        meth = addrxlat.Method(desc)
        self.sys.set_meth(addrxlat.SYS_METH_CUSTOM + 1, meth)
        map.set(0x4000, addrxlat.Range(0x1fff, addrxlat.SYS_METH_CUSTOM + 1))
        map.set(0x6000, addrxlat.Range(0x9fff, addrxlat.SYS_METH_PGT))

        map = addrxlat.Map()
        self.sys.set_map(addrxlat.SYS_MAP_KPHYS_DIRECT, map)
        desc = addrxlat.LinearDescription(addrxlat.KVADDR, -0x1000)
        meth = addrxlat.Method(desc)
        self.sys.set_meth(addrxlat.SYS_METH_RDIRECT, meth)
        map.set(0x1000, addrxlat.Range(0x1fff, addrxlat.SYS_METH_RDIRECT))

        map = addrxlat.Map()
        self.sys.set_map(addrxlat.SYS_MAP_MACHPHYS_KPHYS, map)
        desc = addrxlat.LinearDescription(addrxlat.KPHYSADDR, -0x10000)
        meth = addrxlat.Method(desc)
        self.sys.set_meth(addrxlat.SYS_METH_MACHPHYS_KPHYS, meth)
        map.set(0x10000, addrxlat.Range(0xffff, addrxlat.SYS_METH_MACHPHYS_KPHYS))

        map = addrxlat.Map()
        self.sys.set_map(addrxlat.SYS_MAP_KPHYS_MACHPHYS, map)
        desc = addrxlat.LinearDescription(addrxlat.MACHPHYSADDR, 0x10000)
        meth = addrxlat.Method(desc)
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
        with self.assertRaisesRegexp(addrxlat.NoMethodError, 'No way to translate'):
            addr.conv(addrxlat.MACHPHYSADDR, self.ctx, self.sys)

    def test_fulladdr_conv_machphys_kphys(self):
        "MACHPHYS -> KPHYS using offset"
        addr = addrxlat.FullAddress(addrxlat.MACHPHYSADDR, 0x1abcd)
        addr.conv(addrxlat.KPHYSADDR, self.ctx, self.sys)
        self.assertEqual(addr, addrxlat.FullAddress(addrxlat.KPHYSADDR, 0xabcd))

    def test_fulladdr_fail_machphys_kphys(self):
        "MACHPHYS -> KPHYS out of bounds"
        addr = addrxlat.FullAddress(addrxlat.MACHPHYSADDR, 0xabcd)
        with self.assertRaisesRegexp(addrxlat.NoMethodError, 'No way to translate'):
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
        with self.assertRaisesRegexp(addrxlat.NoMethodError, 'Callback returned None'):
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
                self.read_caps = addrxlat.CAPS(addrxlat.MACHPHYSADDR)
            def cb_read32(self, addr):
                # Memory array at 0x40
                if addr.addr == 0x11000 + 0x40 * 4:
                    return 0x12

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

        self.desc = addrxlat.CustomDescription()
        self.desc.target_as = addrxlat.KPHYSADDR
        self.desc.cb_first_step = first_step
        self.desc.cb_next_step = next_step

        import _test_addrxlat
        self.desc_ext = _test_addrxlat.getCustomDescription(addrxlat.convert)
        self.assertEqual(self.desc_ext.kind, addrxlat.CUSTOM)
        self.assertEqual(self.desc_ext.target_as, addrxlat.NOADDR)
        self.desc_ext.target_as = addrxlat.KPHYSADDR

        self.desc_extmod = _test_addrxlat.getCustomDescription(addrxlat.convert)
        self.desc_extmod.target_as = addrxlat.KPHYSADDR
        self.desc_extmod.cb_next_step = next_step

    def test_customdesc_cb(self):
        step = addrxlat.Step(ctx=self.ctx, desc=self.desc)
        self.assertIs(step.base, None)
        self.desc.cb_first_step(step, 0x1234)
        self.assertEqual(step.base.addrspace, addrxlat.NOADDR)
        self.assertEqual(step.base.addr, 0xabcdef)
        self.assertEqual(step.idx[0], 0x34)
        self.assertEqual(step.idx[1], 0x12)
        self.desc.cb_next_step(step)
        self.assertEqual(step.base.addrspace, addrxlat.NOADDR)
        self.assertEqual(step.base.addr, 0x123456 + 0x12)
        self.assertEqual(step.idx[0], 0x34)
        self.assertEqual(step.idx[1], 0x12)

    def test_customdesc_conv(self):
        sys = addrxlat.System()
        map = addrxlat.Map()
        meth = addrxlat.Method(self.desc)
        sys.set_meth(addrxlat.SYS_METH_CUSTOM, meth)
        map.set(0, addrxlat.Range(0xffff, addrxlat.SYS_METH_CUSTOM))
        sys.set_map(addrxlat.SYS_MAP_KV_PHYS, map)
        addr = addrxlat.FullAddress(addrxlat.KVADDR, 0x2345)
        addr.conv(addrxlat.KPHYSADDR, self.ctx, sys)
        self.assertEqual(addr.addrspace, addrxlat.KPHYSADDR)
        self.assertEqual(addr.addr, 0x123456 + 0x4523)

    def test_customdesc_ext_cb(self):
        step = addrxlat.Step(ctx=self.ctx, desc=self.desc_ext)
        self.assertIs(step.base, None)
        self.desc_ext.cb_first_step(step, 0x1234)
        self.assertEqual(step.base.addrspace, addrxlat.NOADDR)
        self.assertEqual(step.base.addr, 0x4d795f4d61676963)
        self.assertEqual(step.idx[0], 0x34)
        self.assertEqual(step.idx[1], 0x12)
        self.desc_ext.cb_next_step(step)
        self.assertEqual(step.base.addrspace, addrxlat.NOADDR)
        self.assertEqual(step.base.addr, 0x4d61676963546f6f + 0x12)
        self.assertEqual(step.idx[0], 0x34)
        self.assertEqual(step.idx[1], 0x12)

    def test_customdesc_ext_conv(self):
        sys = addrxlat.System()
        map = addrxlat.Map()
        meth = addrxlat.Method(self.desc_ext)
        sys.set_meth(addrxlat.SYS_METH_CUSTOM, meth)
        map.set(0, addrxlat.Range(0xffff, addrxlat.SYS_METH_CUSTOM))
        sys.set_map(addrxlat.SYS_MAP_KV_PHYS, map)
        addr = addrxlat.FullAddress(addrxlat.KVADDR, 0x2345)
        addr.conv(addrxlat.KPHYSADDR, self.ctx, sys)
        self.assertEqual(addr.addrspace, addrxlat.KPHYSADDR)
        self.assertEqual(addr.addr, 0x4d61676963546f6f + 0x4523)

    def test_customdesc_extmod_cb(self):
        step = addrxlat.Step(ctx=self.ctx, desc=self.desc_extmod)
        self.assertIs(step.base, None)
        self.desc_extmod.cb_first_step(step, 0x1234)
        self.assertEqual(step.base.addrspace, addrxlat.NOADDR)
        self.assertEqual(step.base.addr, 0x4d795f4d61676963)
        self.assertEqual(step.idx[0], 0x34)
        self.assertEqual(step.idx[1], 0x12)
        self.desc_extmod.cb_next_step(step)
        self.assertEqual(step.base.addrspace, addrxlat.NOADDR)
        self.assertEqual(step.base.addr, 0x123456 + 0x12)
        self.assertEqual(step.idx[0], 0x34)
        self.assertEqual(step.idx[1], 0x12)

    def test_customdesc_extmod_conv(self):
        sys = addrxlat.System()
        map = addrxlat.Map()
        meth = addrxlat.Method(self.desc_extmod)
        sys.set_meth(addrxlat.SYS_METH_CUSTOM, meth)
        map.set(0, addrxlat.Range(0xffff, addrxlat.SYS_METH_CUSTOM))
        sys.set_map(addrxlat.SYS_MAP_KV_PHYS, map)
        addr = addrxlat.FullAddress(addrxlat.KVADDR, 0x2345)
        addr.conv(addrxlat.KPHYSADDR, self.ctx, sys)
        self.assertEqual(addr.addrspace, addrxlat.KPHYSADDR)
        self.assertEqual(addr.addr, 0x123456 + 0x4523)

if __name__ == '__main__':
    unittest.main()
