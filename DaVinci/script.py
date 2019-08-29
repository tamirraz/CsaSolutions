from scapy.all import *
from PIL import Image
import numpy as np
from sklearn.linear_model import LinearRegression
img = Image.new('RGB', (512,512), "black")
pixels = img.load()
out_file = b''
packets = rdpcap('davinci.pcap')
data_map = {}
curr_x = 0
curr_y = 0
num_del = 0
num_dat = 0
pac_num = 0
lsb_lst = []
for packet in packets:
    if raw(packet)[14:16] == b'\x09\x00':
        #print((raw(packet)[27:]))
        data_buf = raw(packet)[27:]
        out_file += data_buf
        if data_buf[:2] in data_map:
            data_map[data_buf[:2]] += 1
        else:
            data_map[data_buf[:2]] = 1
        if data_buf == b'\xc0\x00\x00\x00\x00\x00\x00\x00\x00\x00':
            num_del += 1
            curr_y += 1
            curr_x = 0
        else:
            num_dat += 1
            #print(curr_x, curr_y)
            val = int(((data_buf[2] << 8) + data_buf[3]) / 65536 * 255)
            pixels[curr_x, curr_y] = (val, val, val)
            #pixels[pac_num % 75, pac_num // 75] = (0, 0, int(((data_buf[2] << 8) + data_buf[3]) / 65536 * 255))
            curr_x += 1
            pac_num += 1
            lsb = val & 1
            lsb_lst.append(lsb)
print(num_dat, num_del)
img.show()
#print((out_file))
f = open('out', 'wb')
f.write(out_file)
f.close()
print(sorted(data_map.items(), key = lambda x: x[1]))
'''
for buf in data_map.keys():
    indices_lst = []
    packet_num = 0
    for packet in packets:
        if raw(packet)[14:16] == b'\x09\x00':
            data_buf = raw(packet)[27:]
            if buf == data_buf:
                indices_lst.append(packet_num)
                x_lst = range(len(indices_lst))
            packet_num += 1
    model = LinearRegression().fit(np.array(x_lst).reshape((-1, 1)), np.array(indices_lst))
    print((buf, model.score(np.array(x_lst).reshape((-1, 1)), np.array(indices_lst))))
'''
'''
cnt = 0
byte_lst = []
for b in lsb_lst:
    if cnt == 0:
        curr_byte = 0
    curr_byte += b << 7 - cnt
    cnt += 1
    if cnt == 8:
        byte_lst.append(curr_byte)
        cnt = 0
print(byte_lst)
for B in byte_lst:
    if B > 31 and B < 128:
        print(chr(B), end='')
'''