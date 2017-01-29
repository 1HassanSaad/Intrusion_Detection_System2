import socket,struct,binascii,time,datetime,os
import MySQLdb

sock_created = False
sniffer_socket = 0
num = 0
retn_data = {'num':'',
			'time':'',
			'ether_type':'',
			'proto':'',
			'src_mac':'',
			'dst_mac':'',
			'src_ip':'',
			'src_port':'',
			'dst_ip':'',
			'dst_port':'',
			'pure_data':'',
			'total_data':''
			}

#get-local-ip#
def get_local_ip():
	try:
		tmp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		tmp.connect(('google.com', 0))
		LOCAL_IP = tmp.getsockname()[0]
		tmp.close()
	except:
		print "Internet Connection Fails : Using Destination IP as 127.0.0.1"
		LOCAL_IP = "127.0.0.1"
	return LOCAL_IP

def clear():
		global retn_data
		retn_data['time'] = ''
		retn_data['ether_type'] = ''
		retn_data['proto'] = ''
		retn_data['src_mac'] = ''
		retn_data['dst_mac'] = ''
		retn_data['src_ip'] = ''
		retn_data['src_port'] = ''
		retn_data['dst_ip'] = ''
		retn_data['dst_port'] = ''
		retn_data['pure_data'] = ''
		retn_data['total_data'] = ''
		return

def analyze_ARP_header(recv_data):
		global retn_data
		arp_hdr = struct.unpack("!1H1H1s1s2s6s4s6s4s",recv_data[:28])
		hard_type=arp_hdr[0]
		proto_type = arp_hdr[1]
		hard_addr = binascii.hexlify(arp_hdr[2]) 
		proto_addr = binascii.hexlify(arp_hdr[3]) 
		operation_code = binascii.hexlify(arp_hdr[4])
		src_mac = binascii.hexlify(arp_hdr[5])
		src_IP = socket.inet_ntoa(arp_hdr[6])
		dst_mac = binascii.hexlify(arp_hdr[7])
		dst_IP =  socket.inet_ntoa(arp_hdr[8])
		
		data = recv_data[28:]
		retn_data['proto'] = "ARP"
		return data

def analyze_RDP_header(recv_data):
		global retn_data
		rdp_hdr = struct.unpack("!2B2BH3I",recv_data[:18])
		flages=rdp_hdr[0]
		headerlen=rdp_hdr[1]
		src_port=rdp_hdr[2]
		dst_port=rdp_hdr[3]
		sec_nu=rdp_hdr[4]
		ack_nu=rdp_hdr[5]
		check=rdp_hdr[6]       
		
		retn_data['src_port'] = src_port
		retn_data['dst_port'] = dst_port

		data = recv_data[18:]
		return data

def analyze_DCCP_header(recv_data):
		global retn_data
		dccp_hdr = struct.unpack("!4HI",recv_data[:12])
		src_port = dccp_hdr[0]
		dst_port = dccp_hdr[1]
		dataofset = dccp_hdr[2] >> 8
		CCVal = dccp_hdr[2] & 0xf0
		CsCov = dccp_hdr[2] & 0x0f
		check = dccp_hdr[3]
		res = dccp_hdr[4] >> 29
		typee = dccp_hdr[4] & 0x1E000000
		x = dccp_hdr[4] & 00001000000 
		receve = dccp_hdr[4] & 0xff0000
		if x == 1:
		     	sequ_nu = dccp_hdr[4] & 0x00ffff

		retn_data['src_port'] = src_port
		retn_data['dst_port'] = dst_port

		data = recv_data[12:]
		return data

def analyze_igmp_header(recv_data):
		global retn_data
		icgp_hdr=struct.unpack("!2H4s",recv_data[:8])
		ver= icgp_hdr[0] >> 12
		typee= icgp_hdr[0] & 0x0f00
		unused= icgp_hdr[0] & 0xff
		cucksum = icgp_hdr[1] 
		group_addr = socket.inet_ntoa(icgp_hdr[2])

		data = recv_data[8:]
		return data

def analyze_icmp_header(recv_data):
		global retn_data
		icmp_hdr  = struct.unpack("!1s1s",recv_data[:2])
		typee = binascii.hexlify(icmp_hdr[0])
		code = binascii.hexlify(icmp_hdr[1])
		data = recv_data[2:]

		return data

def analyze_udp_header(recv_data):
		global retn_data
		udp_hdr  = struct.unpack("!4H",recv_data[:8])
		src_port = udp_hdr[0]
		dst_port = udp_hdr[1]
		length   = udp_hdr[2]
		chk_sum  = udp_hdr[3]
		data     = recv_data[8:]
		
		retn_data['src_port'] = src_port
		retn_data['dst_port'] = dst_port

		return data

def analyze_tcp_header(recv_data):
		global retn_data
		tcp_hdr  = struct.unpack("!2H2I4H",recv_data[:20])
		src_port = tcp_hdr[0]
		dst_port = tcp_hdr[1]
		seq_num  = tcp_hdr[2]
		ack_num  = tcp_hdr[3]
		data_off = tcp_hdr[4] & 0xf000
		reserved = tcp_hdr[4] & 0xF00
		flags    = tcp_hdr[4] & 0xFF
		win_size = tcp_hdr[5]
		chk_sum  = tcp_hdr[6]
		urg_ptr  = tcp_hdr[7]
		data     = recv_data[20:]

		urg = bool(flags & 0x20)
		ack = bool(flags & 0x10)
		psh = bool(flags & 0x8)
		rst = bool(flags & 0x4)
		syn = bool(flags & 0x2)
		fin = bool(flags & 0x1)
		
		retn_data['src_port'] = src_port
		retn_data['dst_port'] = dst_port

		return data

def analyze_ip_header(recv_data):
		global retn_data
		ip_hdr      = struct.unpack("!6H4s4s",recv_data[:20])
		ver = ip_hdr[0] >> 12
		hdr_len     = (ip_hdr[0] >> 8) & 0x0f
		ip_tos      = ip_hdr[0] & 0x00ff
		tot_len     = ip_hdr[1]
		ip_id       = ip_hdr[2]
		flag= ip_hdr[3] & 0xe000
		offset      = ip_hdr[3] & 0x1fff
		ttl = ip_hdr[4] >> 8
		ip_proto    = ip_hdr[4] & 0x00ff
		ip_cksum    = ip_hdr[5]
		src_ip      = socket.inet_ntoa(ip_hdr[6])
		dst_ip      = socket.inet_ntoa(ip_hdr[7])
		data= recv_data[20:]

		retn_data['src_ip'] = src_ip
		retn_data['dst_ip'] = dst_ip

		if ip_proto == 6:
				proto = "TCP"
				retn_data['proto'] = "TCP"
		elif ip_proto == 17:
				proto = "UDP"
				retn_data['proto'] = "UDP"
		elif ip_proto == 1:
				proto = "ICMP"
				retn_data['proto'] = "ICMP"
		elif ip_proto == 2:
				proto = "IGMP"
				retn_data['proto'] = "IGMP"
		elif proto == 27:
				proto = "RDP"
				retn_data['proto'] = "RDP"
		elif ip_proto == 33:
				proto = "DCCP"
				retn_data['proto'] = "DCCP"
		else:
				proto = "OTHER"
				retn_data['proto'] = "OTHER"

		return data

def analyze_ether_header(recv_data):
		global retn_data,num
		eth_hdr    = struct.unpack("!6s6sH",recv_data[:14])
		dst_mac    = binascii.hexlify(eth_hdr[0])
		src_mac    = binascii.hexlify(eth_hdr[1])
		ether_type = eth_hdr[2]
		data       = recv_data[14:]
		
		x=datetime.datetime.now()
		retn_data['time'] = str(x.hour)+":"+str(x.minute)+":"+str(x.second)
		retn_data['num'] = num
		num += 1
		
		retn_data['src_mac'] = str(src_mac[:2])+":"+str(src_mac[2:4])+":"+str(src_mac[4:6])+":"+str(src_mac[6:8])+":"+str(src_mac[8:10])+":"+str(src_mac[10:12])
		retn_data['dst_mac'] = str(dst_mac[:2])+":"+str(dst_mac[2:4])+":"+str(dst_mac[4:6])+":"+str(dst_mac[6:8])+":"+str(dst_mac[8:10])+":"+str(dst_mac[10:12])

		if ether_type == 0x0800: #IPV4
				retn_data['ether_type'] = "IPV4"
				return data
		if ether_type == 0x0806: #ARP
				retn_data['ether_type'] = "ARP"
				return data
		retn_data['ether_type'] = "OTHER"
		return data       #OTHER

def sniffer():
		clear()
		global sock_created,sniffer_socket,retn_data
		if sock_created == False:
				sniffer_socket = socket.socket(socket.PF_PACKET,socket.SOCK_RAW,socket.htons(0x0003))
				sock_created = True
		recv_data = sniffer_socket.recv(2048)
		retn_data['total_data'] = recv_data
		recv_data = analyze_ether_header(recv_data)
		
		if(retn_data['ether_type'] == "IPV4"): #IPV4
				recv_data = analyze_ip_header(recv_data)
		elif(retn_data['ether_type'] == "ARP"): #ARP
				recv_data = analyze_ARP_header(recv_data)
				retn_data['pure_data'] = ''.join([i if (ord(i) < 128 and ord(i) > 31) else '' for i in recv_data])		
				return retn_data
		else:     #OTHER
				retn_data['pure_data'] = ''.join([i if (ord(i) < 128 and ord(i) > 31) else '' for i in recv_data])
				return retn_data
		
		if(retn_data['proto'] == "TCP"):
				recv_data = analyze_tcp_header(recv_data)
		if(retn_data['proto'] == "UDP"):
				recv_data = analyze_udp_header(recv_data)
		if(retn_data['proto'] == "ICMP"):
				recv_data = analyze_icmp_header(recv_data)
		if(retn_data['proto'] == "IGMP"):
				recv_data = analyze_igmp_header(recv_data)
		if(retn_data['proto'] == "DCCP"):
				recv_data = analyze_dccp_header(recv_data)
		if(retn_data['proto'] == "RDP"):
				recv_data = analyze_rdp_header(recv_data)	

		retn_data['pure_data'] = ''.join([i if (ord(i) < 128 and ord(i) > 29) else '' for i in recv_data])
		return retn_data

def database(src,dest,x):
	db=MySQLdb.connect(host="localhost",user="root",passwd="",db="Firewall")
	src_ip  = IpConverter(src)
	dest_ip = IpConverter(dest)
	query = db.cursor()
	query.execute("SELECT * FROM input WHERE RSrc_IP = %s",[src])
	InList = query.rowcount
	if(InList == 0):
		query.execute("INSERT INTO input (Src_IP, Dest_IP, RSrc_IP, RDest_IP , AttackTime) VALUES (%s,%s,%s,%s,%s)",[src_ip,dest_ip,src,dest,x] )
		db.commit()
		rules = open("firee.txt","a")
		rule = "1," + str(src_ip) + ",0," + str(dest_ip) + ",0,0,0,\n"
		rules.write(rule)
		rules.close()
		os.system("bash fire.sh")
		query.execute("SELECT Attacked FROM blacklist WHERE IP = %s",[src])
		InBlack = query.rowcount
		if(InBlack != 0):
			Attacked_Number = query.fetchone();
			Attacked_Number = Attacked_Number[0];
		if(InBlack == 0):
			TTR = str(x.year)+":"+str(x.month)+":"+str(x.day)+":"+str(x.hour+1)+":"+str(x.minute)+":"+str(x.second)
			query.execute("INSERT INTO blacklist (IP,TTR) VALUES (%s,%s)",[src,TTR])
			db.commit()
		else:
			if(Attacked_Number == 1):
				Attacked_Number += 1
				TTR = str(x.year)+":"+str(x.month)+":"+str(x.day+1)+":"+str(x.hour)+":"+str(x.minute)+":"+str(x.second)
				query.execute ("UPDATE blacklist SET TTR= %s,Attacked= %s WHERE IP= %s",[TTR,Attacked_Number,src])
				db.commit()
			elif(Attacked_Number == 2):
				Attacked_Number += 1
				TTR = str(x.year)+":"+str(x.month)+":"+str(x.day+7)+":"+str(x.hour)+":"+str(x.minute)+":"+str(x.second)
				query.execute ("UPDATE blacklist SET TTR= %s,Attacked= %s WHERE IP= %s",[TTR,Attacked_Number,src])
				db.commit()
			elif(Attacked_Number == 3):
				Attacked_Number += 1
				TTR = str(x.year)+":"+str(x.month+1)+":"+str(x.day)+":"+str(x.hour)+":"+str(x.minute)+":"+str(x.second)
				query.execute ("UPDATE blacklist SET TTR= %s,Attacked= %s WHERE IP= %s",[TTR,Attacked_Number,src])
				db.commit()
			else:
				Attacked_Number += 1
				TTR = str(x.year+1)+":"+str(x.month)+":"+str(x.day)+":"+str(x.hour)+":"+str(x.minute)+":"+str(x.second)
				query.execute ("UPDATE blacklist SET TTR= %s,Attacked= %s WHERE IP= %s",[TTR,Attacked_Number,src])
				db.commit()

	#quary.execute("select AttackTime from input where RSrc_IP = src")
	db.close()
def IpConverter(ip):
	ip=ip.split('.',3);
	ip.reverse();
	z=[]
	for i in range(0,4):
		z.append(int(ip[i]));

	for i in range(0,4):
		z[i]=format(z[i],'08b')

	ip=z[0]+z[1]+z[2]+z[3];
	ip=int(ip, 2)
	return ip;








