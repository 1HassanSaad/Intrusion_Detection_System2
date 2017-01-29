from LIB import sniffer,get_local_ip,database
import threading,datetime,time

ip_ports = {}
LOCAL_IP = get_local_ip()
		
def main():
	global ip_ports
	while(True):        
		retn_data = sniffer()
		if retn_data['proto'] == 'TCP':
			if retn_data['dst_ip'] == LOCAL_IP :
				if retn_data['src_ip'] not in ip_ports :
					ip_ports[retn_data['src_ip']] = [retn_data['dst_port']]
				else:
					if retn_data['dst_port'] not in ip_ports[retn_data['src_ip']]:
						ip_ports[retn_data['src_ip']] += [retn_data['dst_port']]

def output():
	global ip_ports
	while(True):
		file1 = open("Detection Algorithms/SCAN_details","a")
		x=datetime.datetime.now()
		file1.write("data="+str(x.year)+":"+str(x.month)+":"+str(x.day)+":"+str(x.hour)+":"+str(x.minute)+":"+str(x.second)+"\n")
		file1.close()
		time.sleep(30)
		file1 = open("Detection Algorithms/SCAN_details","a")
		file2 = open("Detection Algorithms/ATTACK_details","a")
		for ip,ports in ip_ports.iteritems():
			num_of_ports = ports.__len__()
			file1.write(str(ip) + " , num of ports = " + str(num_of_ports) + "\n")
			if num_of_ports > 50:
				file2.write(str(ip) + " Port Scanning Attack , "+"data="+str(x.year)+":"+str(x.month)+":"+str(x.day)+":"+str(x.hour)+":"+str(x.minute)+":"+str(x.second)+"\n" )
				print str(ip) + " Port Scanning Attack , "+"data="+str(x.year)+":"+str(x.month)+":"+str(x.day)+":"+str(x.hour)+":"+str(x.minute)+":"+str(x.second)+"\n"
				database(ip,LOCAL_IP,x)
		file1.close()
		file2.close()
		ip_ports = {}

t1=threading.Thread(target=main)
t2=threading.Thread(target=output)
t1.start()
t2.start()

