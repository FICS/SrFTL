#!/bin/bash
# Run VM with sgx and FEMU support: FEMU as a black-box SSD (FTL managed by the device)

# image directory
IMGDIR=$HOME/images
# virtual machine disk image
OSIMGF=$IMGDIR/u14s.qcow2.versioning.backup_unaffected

if [[ ! -e "$OSIMGF" ]]; then
	echo ""
	echo "VM disk image couldn't be found ..."
	echo "Please prepare a usable VM image and place it as $OSIMGF"
	echo "Once VM disk image is ready, please rerun this script again"
	echo ""
	exit
fi

sudo x86_64-softmmu/qemu-system-x86_64 \
    -name "FEMU-blackbox-SSD" \
    -enable-kvm \
    -cpu host,+sgx,-sgxlc \
    -object memory-backend-epc,id=mem1,size=80M,prealloc -sgx-epc id=epc1,memdev=mem1 \
    -smp 4 \
    -m 4G \
    -device virtio-scsi-pci,id=scsi0 \
    -device scsi-hd,drive=hd0 \
    -drive file=$OSIMGF,if=none,aio=native,cache=none,format=qcow2,id=hd0 \
    -device femu,devsz_mb=10240,femu_mode=1 \
    -nographic \
    -net user,hostfwd=tcp::8080-:22 \
    -net nic,model=virtio \
    -vga std \
    -qmp unix:./qmp-sock,server,nowait 2>&1 | tee log 


