import sys
import math

THRESHOLD = 293.247835

def entropy_calculation(filename):
    global THRESHOLD
    fd = open(filename, 'r')
    total_chunks = 0
    encrypted_chunks = 0
    high_entropy_chunks = 0
    low_chisquare_chunks = 0
    while 1:
        buf = fd.read(4096)
        if not buf:
            break
        total_chunks += 1
        byteList = list(buf)
        data_len = len(byteList)
        byte_freq_list = []

        expected_freq = float (data_len) / 256

        for num in range(256):
            count = 0

            for byte in byteList:
                if ord(byte) == num:
                    count += 1
            byte_freq_list.append(float(count))

        chisquare = 0.0
        entropy = 0.0

        for freq in byte_freq_list:
            diff = freq - expected_freq
            diff_square = diff*diff
            chisquare += diff_square

            if freq > 0:
                entropy += (freq/data_len) * (-1 * math.log((freq/data_len), 2))
        chisquare /= expected_freq


#        print(chisquare)
        if chisquare <= THRESHOLD and entropy > 7:
            encrypted_chunks += 1
        if chisquare <= THRESHOLD:
            low_chisquare_chunks += 1
        if entropy > 7:
            high_entropy_chunks += 1

    print("Total chunks number is: ", total_chunks)
    print("Encrypted chunks number is: ", encrypted_chunks)
    print("High entropy chunks number is: ", high_entropy_chunks)
    print("Low chi-square chunks number is: ", low_chisquare_chunks)

if len(sys.argv) != 2:
    print("Parameter number wrong!")
    sys.exit()

filename = sys.argv[1]

entropy_calculation(filename)
