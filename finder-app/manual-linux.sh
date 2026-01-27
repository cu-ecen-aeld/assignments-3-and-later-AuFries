#!/bin/bash
# Script outline to install and build kernel.
# Author: Siddhant Jajoo.

set -e
set -u

OUTDIR=/tmp/aeld
OUTROOT="$OUTDIR/rootfs"
LOGFILE=out.log
KERNEL_REPO=git://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git
KERNEL_VERSION=v5.15.163
BUSYBOX_VERSION=1_33_1
FINDER_APP_DIR=$(realpath $(dirname $0))
ARCH=arm64
CROSS_COMPILE=aarch64-none-linux-gnu-
LIB=/home/aufries/arm-cross-compiler/arm-gnu-toolchain-13.3.rel1-x86_64-aarch64-none-linux-gnu/bin/../aarch64-none-linux-gnu/libc/lib64

# Redirect stdout to both log and terminal
exec > >(tee -a "$LOGFILE") 2>&1

if [ $# -lt 1 ]
then
	echo "Using default directory ${OUTDIR} for output"
else
	OUTDIR=$1
	echo "Using passed directory ${OUTDIR} for output"
fi

mkdir -p ${OUTDIR}

cd "$OUTDIR"
if [ ! -d "${OUTDIR}/linux-stable" ]; then
    #Clone only if the repository does not exist.
	echo "CLONING GIT LINUX STABLE VERSION ${KERNEL_VERSION} IN ${OUTDIR}"
	git clone ${KERNEL_REPO} --depth 1 --single-branch --branch ${KERNEL_VERSION}
fi
if [ ! -e ${OUTDIR}/linux-stable/arch/${ARCH}/boot/Image ]; then
    cd linux-stable
    echo "Checking out version ${KERNEL_VERSION}"
    git checkout ${KERNEL_VERSION}

    # kernel build steps here
    echo "Starting kernel build"
    echo "make mrproper"
    make ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE} mrproper # deep clean kernel source tree
    echo "make defconfig"
    make ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE} defconfig # configure for virtual arm dev board
    echo "make all"
    make -j4 ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE} all # build kernel image
    # echo "make modules" (Skip as described in instructions)
    # make ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE} modules # build modules
    echo "make dtbs"
    make ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE} dtbs # build device trees
fi

echo "Adding the Image in outdir"
cp linux-stable/arch/${ARCH}/boot/Image ${OUTDIR}/

echo "Creating the staging directory for the root filesystem"
cd "$OUTDIR"
if [ -d "${OUTDIR}/rootfs" ]
then
	echo "Deleting rootfs directory at ${OUTDIR}/rootfs and starting over"
    sudo rm  -rf ${OUTDIR}/rootfs
fi
mkdir rootfs

# Create necessary base directories
cd ${OUTROOT}
echo "Creating necessary base directories"
mkdir -p bin dev etc home lib lib64 proc sbin sys tmp usr var
mkdir -p user/bin usr/lib usr/sbin
mkdir -p var/log

cd "$OUTDIR"
if [ ! -d "${OUTDIR}/busybox" ]
then
git clone git://busybox.net/busybox.git
    cd busybox
    git checkout ${BUSYBOX_VERSION}
    # Configure busybox
    echo "Configuring busybox"
    make distclean
    make defconfig
else
    cd busybox
fi

# Make and install busybox
echo "Building busybox"
make ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE}
make CONFIG_PREFIX=${OUTDIR}/rootfs ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE} install

echo "Library dependencies"
cd ${OUTROOT}
${CROSS_COMPILE}readelf -a bin/busybox | grep "program interpreter"
${CROSS_COMPILE}readelf -a bin/busybox | grep "Shared library"

# Add library dependencies to rootfs
echo "Adding library dependencies"
SYSROOT_LIB=$(${CROSS_COMPILE}gcc --print-sysroot)
# find "$SYSROOT_LIB" \( -name 'libm.so*' -o -name 'libc.so*' -o -name 'libresolv.so*' \) -print
cp -a "$SYSROOT_LIB/lib64/libm.so.6"       "$OUTROOT/lib64/"
cp -a "$SYSROOT_LIB/lib64/libresolv.so.2"  "$OUTROOT/lib64/"
cp -a "$SYSROOT_LIB/lib64/libc.so.6"       "$OUTROOT/lib64/"
cp -a "$SYSROOT_LIB/lib/ld-linux-aarch64.so.1" "$OUTROOT/lib/"

# Make device nodes
echo "Making null and console device nodes"
sudo mknod -m 666 dev/null c 1 3
sudo mknod -m 666 dev/console c 5 1

# Clean and build the writer utility
cd ${FINDER_APP_DIR}
make clean
make CROSS_COMPILE=${CROSS_COMPILE}

# Copy the finder related scripts and executables to the /home directory
# on the target rootfs
cp -a writer "$OUTROOT/home"
mkdir -p "$OUTROOT/home/conf"
cp -a conf/username.txt "$OUTROOT/home/conf"
cp -a conf/assignment.txt "$OUTROOT/home/conf"
cp -a finder-test.sh "$OUTROOT/home"
cp -a finder.sh "$OUTROOT/home"
cp -a autorun-qemu.sh "$OUTROOT/home"

# Chown the root directory
sudo chown -R root:root ${OUTROOT}

# Create initramfs.cpio.gz (disk loaded into RAM by bootloader)
# Bundles rootfs into a format understood by QEMU
cd ${OUTROOT}
find . | cpio -H newc -ov --owner root:root > ${OUTDIR}/initramfs.cpio
cd ${OUTDIR}
gzip -f initramfs.cpio