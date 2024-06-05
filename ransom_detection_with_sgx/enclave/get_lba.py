import os
import time
import sys

lba_file_info = {}

default_str = "sudo hdparm --fibmap "

def directory_traverse(folder):
    files = os.listdir(folder)

    for file in files:
        file = file.replace(' ', '\\ ')
        if not os.path.isdir(folder + "/" + file):
            command = default_str + folder + "/" + file
            c_str = os.popen(command).read()
            output_lines = c_str.split("\n")
            if len(output_lines) < 5:
                continue
            lba_line = output_lines[4]
            lba_line_elements = lba_line.split()
            start_lba = lba_line_elements[1]
            sectors = lba_line_elements[3]

            st = os.stat(folder + "/" + file)
            m_time_hours = st.st_mtime / 3600
            nlink = st.st_nlink
            byte_size = st.st_size
            mid_file = file.replace('\\ ', '')

            command = "file " + folder + "/" + file
            c_str=os.popen(command).read()
            time.sleep(0.1)
            c_str = c_str.replace('\n', '')
            c_str = c_str.replace(' ', '')


            output = c_str.split(':')
            output = output[1].split(",")

            info = [mid_file, sectors, m_time_hours, nlink, byte_size,output[0]]

            lba_file_info[start_lba] = info
        else:
            directory_traverse(folder + "/" + file)






para_len = len(sys.argv)

if para_len != 2:
    print("Parameter error!\n")
    exit(0)

folder_name = sys.argv[1]

directory_traverse(folder_name)

if os.path.exists("mapping.tbl"):
    os.remove("mapping.tbl")
fd = open("mapping.tbl", 'w')

for key in lba_file_info:
    line_str = key
    info = lba_file_info[key]
    type_name = info[5]
    line_str = line_str + ',' + info[0] + ',' + info[1]
    line_str = line_str + ',' + str(info[2]) + ',' + str(info[3]) + ',' + str(info[4]) + ',' + type_name[0:39]
    line_str = line_str + '\n'
    fd.write(line_str)
fd.close()
