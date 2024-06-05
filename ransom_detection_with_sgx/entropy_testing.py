import sys
import math

def entropy_calculation(filename):
    fd = open(filename, 'r')
    total_chunks = 0
    encrypted_chunks = 0
    while 1:
        buf = fd.read(256)
        if not buf:
            break
        total_chunks += 1
        byteList = list(buf)
        data_len = len(byteList)
        byte_freq_list = []

        for num in range(256):
            count = 0

            for byte in byteList:
                if ord(byte) == num:
                    count += 1
            byte_freq_list.append(float(count)/data_len)

        entropy = 0.0
        for freq in byte_freq_list:
            if freq > 0:
                entropy += freq * (-1 * math.log(freq, 2))
        if entropy > 7:
            encrypted_chunks += 1

    print("Total chunks number is: ", total_chunks)
    print("Encrypted chunks number is: ", encrypted_chunks)

if len(sys.argv) != 2:
    print("Parameter number wrong!")
    sys.exit()

filename = sys.argv[1]

entropy_calculation(filename)
