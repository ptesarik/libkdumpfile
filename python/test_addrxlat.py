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

    def test_fulladdr_conv(self):
        ctx = addrxlat.Context()
        desc = addrxlat.LinearDescription(addrxlat.KPHYSADDR, 0xf0000)
        meth = addrxlat.Method(desc)
        map = addrxlat.Map()
        map.set(0, addrxlat.Range(0xffff, meth))
        sys = addrxlat.System()
        sys.set_map(addrxlat.SYS_MAP_KV_PHYS, map)
        addr = addrxlat.FullAddress(addrxlat.KVADDR, 0x1234)
        addr.conv(addrxlat.KPHYSADDR, ctx, sys)
        self.assertEqual(addr, addrxlat.FullAddress(addrxlat.KPHYSADDR, 0xf1234))

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
        desc = addrxlat.LinearDescription(off=0x1234)
        self.assertEqual(desc.kind, addrxlat.LINEAR)
        self.assertEqual(desc.target_as, addrxlat.NOADDR)
        self.assertEqual(desc.off, 0x1234)

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
        self.assertEqual(range.meth, None)

    def test_range_endoff(self):
        range = addrxlat.Range(endoff=0x1234)
        self.assertEqual(range.endoff, 0x1234)
        self.assertEqual(range.meth, None)

    def test_range_meth(self):
        meth = addrxlat.Method()
        range = addrxlat.Range(meth=meth)
        self.assertEqual(range.endoff, 0)
        self.assertIs(range.meth, meth)

class TestMap(unittest.TestCase):
    def test_map_defaults(self):
        map = addrxlat.Map()
        self.assertEqual(len(map), 0)

    def test_map_set(self):
        map = addrxlat.Map()
        meth = addrxlat.Method()
        map.set(0, addrxlat.Range(0xffff, meth))
        self.assertEqual(len(map), 2)
        self.assertEqual(map[0].endoff, 0xffff)
        self.assertEqual(map[0].meth, meth)
        self.assertIs(map[1].meth, None)

    def test_map_search(self):
        map = addrxlat.Map()
        meth = addrxlat.Method()
        map.set(0, addrxlat.Range(0xffff, meth))
        meth2 = map.search(0)
        self.assertEqual(meth2, meth)
        meth2 = map.search(0x10000)
        self.assertIs(meth2, None)

    def test_map_clear(self):
        map = addrxlat.Map()
        meth = addrxlat.Method()
        map.set(0, addrxlat.Range(0xffff, meth))
        self.assertEqual(len(map), 2)
        map.clear()
        self.assertEqual(len(map), 0)

    def test_map_dup(self):
        map = addrxlat.Map()
        meth = addrxlat.Method()
        map.set(0, addrxlat.Range(0xffff, meth))
        self.assertEqual(len(map), 2)
        map2 = map.dup()
        self.assertNotEqual(map2, map)
        self.assertEqual(len(map2), 2)
        self.assertEqual(map2[0].endoff, map[0].endoff)
        self.assertEqual(map2[0].meth, map[0].meth)
        self.assertEqual(map2[1].endoff, map[1].endoff)
        self.assertIs(map2[1].meth, None)

class TestSystem(unittest.TestCase):
    "TODO"

class TestStep(unittest.TestCase):
    "TODO"

class TestOperator(unittest.TestCase):
    "TODO"

if __name__ == '__main__':
    unittest.main()
