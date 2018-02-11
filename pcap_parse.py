#coding=utf-8
#!/usr/bin/python  
  
import sys  
import socket  
import struct  
  
filename = sys.argv[1]  
ipaddr = sys.argv[2]  
direction = sys.argv[3]  
  
packed = socket.inet_aton(ipaddr)  
'''
大端字节序
>: big-endian, std. size & alignment
!: same as >
'''
ip32 = struct.unpack("!L", packed)[0]  
  
file = open(filename, "rb")   
  
'''
pcap_file_header的长度, 格式如下:
struct pcap_file_header {
    bpf_u_int32 magic;
    u_short version_major;
    u_short version_minor;
    bpf_int32 thiszone;    /* gmt to local correction */
    bpf_u_int32 sigfigs;    /* accuracy of timestamps */
    bpf_u_int32 snaplen;    /* max length saved portion of each pkt */
    bpf_u_int32 linktype;    /* data link type (LINKTYPE_*) */
};
'''
pcaphdrlen = 24 

'''
一个数据包的描述头, 格式如下:
struct pcap_pkthdr {
    struct timeval ts;    /* time stamp */
    bpf_u_int32 caplen;    /* length of portion present 由于tcpdump可以设置-s参数指定抓取的长度，这个字段表示实际抓取的数据包长度 */
    bpf_u_int32 len;    /* length this packet (off wire) 这个字段表示数据包的自然长度 */
};
'''
pkthdrlen=16  
pkthdrlen1=14
  
iphdrlen=20  
tcphdrlen=20  
stdtcp = 20  

total = 0  
pos = 0  
  
start_seq = 0  
end_seq = 0  
cnt = 0  
  
# Read 24-bytes pcap header  
data = file.read(pcaphdrlen) 
'''
例如:(2712847316, '\x00', '\x00', 0, 0, 65535, 1)
最后一个1代表 以太网,如下图所示:
LINKTYPE_ETHERNET	1	D/I/X and 802.3 Ethernet
''' 
(tag, maj, min, tzone, ts, ppsize, lt) = struct.unpack("=L2p2pLLLL", data)  

# 具体的LinkType细节，请看：  
# http://www.winpcap.org/ntar/draft/PCAP-DumpFileFormat.html#appendixBlockCodes  
if lt == 0x71: 
    #Cooked Capture 
    pkthdrlen1 = 16  
else:  
    #Ethernet
    pkthdrlen1 = 14  
  
ipcmp = 0  
  
# Read 16-bytes packet header
# 读出一个数据包的描述头信息  
data = file.read(pkthdrlen)  
  
while data: 
    '''
        struct pcap_pkthdr {  
            struct timeval ts;    /* time stamp */  
            bpf_u_int32 caplen;    /* length of portion present 由于tcpdump可以设置-s参数指定抓取的长度，这个字段表示实际抓取的数据包长度 */  
            bpf_u_int32 len;    /* length this packet (off wire) 这个字段表示数据包的自然长度 */  
        };  
        下面解析为什么会有四个值呢?
        因为struct timeval结构体中存在两个成员sec和microsec
    '''
    #解析如下: (1514913004, 86422, 62, 62), 即一个数据包的描述头，可以在Wireshark中看到 
    (sec, microsec, iplensave, origlen) = struct.unpack("=LLLL", data)  
    '''
        接下来就是各个协议头的头信息了，依次为链路层、IP层和TCP层
    '''
    # read link 
    '''
        typedef struct {
            unsigned char   dest_mac[6];
            unsigned char   src_mac[6];
            unsigned short  eth_type;
        } ethernet_header;
    ''' 
    link = file.read(pkthdrlen1)
    #('\xac\x85=\xac!\x01', '\xf8J\xbf\xfa+\xb7', 2048) 2048即0x0800, 即IP协议  
    #(dst, src, type_ip) = struct.unpack(">6s6sH",link)
    #print(dst, src, type_ip)
    #sys.exit(-1)

    # read IP header  
    data = file.read(iphdrlen) 
    '''
    typedef struct _iphdr //定义IP首部
　　{
　　    unsigned char h_lenver; //4位首部长度+4位IP版本号
　　    unsigned char tos; //8位服务类型TOS
　　    unsigned short total_len; //16位总长度（字节）
　　    unsigned short ident; //16位标识
　　    unsigned short frag_and_flags; //3位标志位
　　    unsigned char ttl; //8位生存时间 TTL
　　    unsigned char proto; //8位协议 (TCP, UDP 或其他)
　　    unsigned short checksum; //16位IP首部校验和
　　    unsigned int sourceIP; //32位源IP地址
　　    unsigned int destIP; //32位目的IP地址
　　}IP_HEADER;
    ''' 
    (vl, tos, tot_len, id, frag_off, ttl, protocol, check, saddr, daddr) = struct.unpack(">ssHHHssHLL", data)  
    '''
      ord(x)	将一个字符转换为它的整数值
      chr(x)	将一个整数转换为一个字符
    '''
    iphdrlen = ord(vl) & 0x0F #取首部长度   
    iphdrlen *= 4  
    #print(iphdrlen)
  
    # read TCP standard header  
    tcpdata = file.read(stdtcp) 
    '''
        TCP首部结构如下所示:
        typedef struct _TCPHdr
        {
            u_int16_t th_sport;     /* source port */
            u_int16_t th_dport;     /* destination port */
            u_int32_t th_seq;       /* sequence number */
            u_int32_t th_ack;       /* acknowledgement number */
            u_int8_t th_offx2;     /* offset and reserved */
            u_int8_t th_flags;
            u_int16_t th_win;       /* window */
            u_int16_t th_sum;       /* checksum */
            u_int16_t th_urp;       /* urgent pointer */
       } TCPHdr;
    '''  
    (sport, dport, seq, ack_seq, pad1, win, check, urgp) = struct.unpack(">HHLLHHHH", tcpdata)  
    tcphdrlen = pad1 & 0xF000  #取TCP首部长度
    tcphdrlen = tcphdrlen >> 12    #??? 
    tcphdrlen = tcphdrlen * 4  
    
    #定义方向为出去的 
    if direction == 'out':  
        ipcmp = saddr #当定义为发送方向时，saddr就为原地址了 
    else:  
        ipcmp = daddr #否则为目的地址
    #确定为所要定位的IP
    if ipcmp == ip32:  
        cnt += 1  
        total += tot_len  #加上ip层统计的总长度
        total -= (iphdrlen + tcphdrlen)  #减去IP+TCP的头长度
        if start_seq == 0:  # BUG?  
            start_seq = seq
        end_seq = seq + tot_len - (iphdrlen + tcphdrlen)
        #end_seq = seq
  
    # skip data 
    skip = file.read(iplensave - pkthdrlen1 - iphdrlen - stdtcp) #这里得把选项也跳过 
  
    # read next packet  
    pos += 1  
    data = file.read(pkthdrlen)  
'''
    这里如果不准的话，可以先检查pcap包是否完整，pcap包未完整自然前面的实际传输的字节数小于应该传输的字节数
''' 
# 打印出实际传输的字节数，以及本应该传输的字节数  
print pos, cnt, 'Actual:'+str(total),  'ideal:'+str(end_seq-start_seq)  
