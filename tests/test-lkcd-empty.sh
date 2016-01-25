#! /bin/sh

#
# test-lkcd-empty.sh
#
# Create an empty LKCDv9 dump file and verify meta-attributes.
#

dumpfile=${0%.sh}.dump

panic="Test panic string"
node=test-node
sysname=Linux
release=3.4.5-test
version="#1 SMP Fri Jan 22 14:02:42 UTC 2016 (1234567)"
machine=x86_64
domain="(none)"

./mklkcd <<EOF $dumpfile
arch_name = x86_64
page_shift = 12
page_offset = 0x0000010000000000
panic_string = $panic

uts.sysname = $sysname
uts.nodename = $node
uts.release = $release
uts.version = $version
uts.machine = $machine
uts.domainname = $domain

NR_CPUS = 8
num_cpus = 1
EOF
rc=$?
if [ $rc -ne 0 ]; then
    echo "Cannot create lkcd file" >&2
    exit $rc
fi
echo "Created empty LKCD dump: $dumpfile"

./checkattr <<EOF $dumpfile
arch = directory:
arch.name = string: x86_64
arch.byte_order = number: 1
arch.ptr_size = number: 8
arch.page_shift = number: 12
arch.page_size = number: 4096

linux = directory:
linux.version_code = number: 0x030405
linux.uts = directory:
linux.uts.sysname = string: $sysname
linux.uts.nodename = string: $node
linux.uts.release = string: $release
linux.uts.version = string: $version
linux.uts.machine = string: $machine
linux.uts.domainname = string: $domain
EOF
rc=$?
if [ $rc -ne 0 ]; then
    echo "Attribute check failed" >&2
    exit $rc
fi

exit 0
