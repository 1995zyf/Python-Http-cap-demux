#!/usr/bin/python
#coding=utf-8

import os
import sys
import socket
import struct

filename = sys.argv[1]
file = open(filename, "rb") 

pcaphdrlen = 24
pkthdrlen=16
linklen=14
iphdrlen=20
tcphdrlen=20
stdtcp = 20

dirname = filename[:filename.find(".pcap")]
if os.path.isdir(dirname):
   pass
else:
   os.mkdir(dirname)

files4out = {}

# Read 24-bytes pcap header
datahdr = file.read(pcaphdrlen)
(tag, maj, min, tzone, ts, ppsize, lt) = struct.unpack("=L2p2pLLLL", datahdr)

# 判断链路层是Cooked还是别的
if lt == 0x71:
	linklen = 16
else:
	linklen = 14

# Read 16-bytes packet header
data = file.read(pkthdrlen)

while data:
	ipsrc_tag = 0
	ipdst_tag = 0
	sport_tag = 0
	dport_tag = 0

	(sec, microsec, iplensave, origlen) = struct.unpack("=LLLL", data)

	# read link
	link = file.read(linklen)
	
	# read IP header
	ipdata = file.read(iphdrlen)
	(vl, tos, tot_len, id, frag_off, ttl, protocol, check, saddr, daddr) = struct.unpack(">ssHHHssHLL", ipdata)
	iphdrlen = ord(vl) & 0x0F 
	iphdrlen *= 4

	# read TCP standard header
	tcpdata = file.read(stdtcp)	
	(sport, dport, seq, ack_seq, pad1, win, check, urgp) = struct.unpack(">HHLLHHHH", tcpdata)
	tcphdrlen = pad1 & 0xF000
	tcphdrlen = tcphdrlen >> 12
	tcphdrlen = tcphdrlen*4

	# skip data
	skip = file.read(iplensave-linklen-iphdrlen-stdtcp)

        '''
            --------------------start---------------------
            2091357539 43402 3721177915 80
            124.167.149.99 43402 221.204.171.59 80
            --------------------end-----------------------
            socket.inet_ntoa(packed_ip): 转换32位打包的IPV4地址为IP地址的标准点号分隔字符串表示。
            socket.htonl(x): 类似于C语言的htonl(x),把32位正整数从主机字节序转换成网络序。

            struct.pack用于将Python的值根据格式符，转换为字符串（因为Python中没有字节(Byte)类型，可以把这里的字符串理解为字节流，或字节数组）。
            struct.unpack做的工作刚好与struct.pack相反，用于将字节流转换成python数据类型。
        '''
	src_tag = socket.inet_ntoa(struct.pack('I',socket.htonl(saddr)))
	dst_tag = socket.inet_ntoa(struct.pack('I',socket.htonl(daddr)))
	sp_tag = str(sport)
	dp_tag = str(dport)
        #print '--------------------start---------------------'
        #print saddr, sport, daddr, dport
        #print src_tag, sp_tag, dst_tag, dp_tag
        #print '--------------------end-----------------------'

	# 此即将四元组按照固定顺序排位，两个方向变成一个方向，保证四元组的唯一性
	if saddr > daddr:
		temp = dst_tag
		dst_tag = src_tag
		src_tag = temp
	if sport > dport:
		temp = sp_tag
		sp_tag = dp_tag
		dp_tag = temp
	
	name = src_tag + '_' + sp_tag + '_' + dst_tag + '_' + dp_tag
	
	if name in files4out:
		file_out = files4out[name]
		file_out.write(data)
		file_out.write(link)
		file_out.write(ipdata)
		file_out.write(tcpdata)
		file_out.write(skip)
		files4out[name] = file_out
	else:
		file_out = open(dirname + '/' + name + '.pcap', "wb")
		file_out.write(datahdr)
		file_out.write(data)
		file_out.write(link)
		file_out.write(ipdata)
		file_out.write(tcpdata)
		file_out.write(skip)
		files4out[name] = file_out

	# read next packet
	data = file.read(pkthdrlen)

file.close()
for file_out in files4out.values():
	file_out.close()
