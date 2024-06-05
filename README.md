# SrFTL: Minding the Semantic Gap for Effective Storage-Based Ransomware Defense

## Introduction

SrFTL is a ransomware defense framework that bridges heuristics and semantic knowledge with SSD’s flash translation layer (FTL) to enhance the detection of encryption ransomware, even in the presence of privilege escalation. SrFTL enforces policy within the SSD, while our improved ransomware classification combines content and behavior-based heuristics for detection. Classification occurs within an enclave, allowing designers to customize the detection policy and leverage multiple semantic information and I/O access patterns that are visible to the host’s filesystem but not only at the storage level, to identify ransomware activity.

```
@inproceedings{SrFTL:MSST2024,
  author = {Weidong Zhu and Grant Hernandez and Washington Garcia and Dave (Jing) Tian and Sara Rampazzi and Kevin R. B. Butler},
  title = {Minding the Semantic Gap for Effective Storage-Based Ransomware Defense},
  booktitle = {Proceedings of the 38th International Conference on Massive Storage Systems and Technology (MSST)},
  address = {Santa Clara, CA},
  month = {June},
  year = {2024},
}
```

## Repository Overview

This repository contains the source code of SrFTL. Our implementation establishes an emulated SSD in the QEMU and then run the guest machine, which initiates the classification enclave to communitate with the SSD for ransomware defense in the device. Meanwhile, the enclave is lauched within the Intel SGX. To enable the establishment of SGX enclave in the guest machine, we port the [qemue-sgx](https://github.com/intel/qemu-sgx) in to [FEMU](https://github.com/MoatLab/FEMU), which contains a SSD emulator established on QEMU. Therefore, our repository mainly comprises of two part.

`srftl_qemu/` contains the QEMU, which combines [qemue-sgx](https://github.com/intel/qemu-sgx) and [FEMU](https://github.com/MoatLab/FEMU).

`ransom_detection_with_sgx/` contains the classification enclave that allows the creation of the enclave application in the hardware SGX.

## Installation

To run this source code, your system must have Intel processor that supports SGX and Ubuntu 18.04. Then, you can run the following commands to install the QEMU virtual machine.

```bash
cd srftl_qemu/build/
./install.sh
```

Once you finish the compilation, you can initiate the guest OS by running:

```bash
./run-blackbox.sh
```

Before you run the VM, you need to create a VM image and install guest OS on it.

Finally, you can start the guest OS. Then, you need to run the classification enclave by running the following commands:

```bash
cd ransom_detection_with_sgx/enclave
make
sudo ./app
```


