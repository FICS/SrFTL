#!/bin/bash

#sudo python get_lba.py /home/weidong/femu_dir
# Disable write buffer
echo 1 | sudo tee /proc/sys/vm/dirty_ratio

# Disable read buffer
echo 0 | sudo tee /proc/sys/vm/drop_caches
