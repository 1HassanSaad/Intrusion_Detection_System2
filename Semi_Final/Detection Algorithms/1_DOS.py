from LIB import sniffer,get_local_ip
import threading,datetime,time

ip_count = {}
LOCAL_IP = get_local_ip()

def main():
	global ip_count
	while 1:		
		retn_data = sniffer()
		data_size = retn_data['total_data'].__len__()
		if retn_data['dst_ip'] == LOCAL_IP :
			if retn_data['src_ip'] in ip_count:
				ip_count[retn_data['src_ip']][0] += 1
				ip_count[retn_data['src_ip']][1] += data_size
			else:
				ip_count[retn_data['src_ip']] = [1]
				ip_count[retn_data['src_ip']] += [data_size]
					   
def output():
	global ip_count
	while(True):
		file1 = open("Detection Algorithms/DOS_details","a")
		x=datetime.datetime.now()
		file1.write("data="+str(x.year)+":"+str(x.month)+":"+str(x.day)+":"+str(x.hour)+":"+str(x.minute)+":"+str(x.second)+"\n")
		file1.close()
		time.sleep(30)
		file1 = open("Detection Algorithms/DOS_details","a")
		file2 = open("Detection Algorithms/ATTACK_details","a")
		for ip,count in ip_count.iteritems():
			file1.write(str(ip)+ " num of packets = "+ str(count[0]) +" , size "+str(count[1])+" bytes\n")
			if count[0] > 30000 or count[1] > 10000000 :
				file2.write(str(ip) + " Denial Of Service Attack 'SIZE' , "+"data="+str(x.year)+":"+str(x.month)+":"+str(x.day)+":"+str(x.hour)+":"+str(x.minute)+":"+str(x.second)+"\n" )
				print str(ip) + " Denial Of Service Attack , "+"data="+str(x.year)+":"+str(x.month)+":"+str(x.day)+":"+str(x.hour)+":"+str(x.minute)+":"+str(x.second)+"\n"	
		
		num_packets = 0
		size_packets = 0
		for value in ip_count.itervalues():
			num_packets += value[0]
			size_packets += value[1]
		
		file1.write("Total Data = "+ str(num_packets) + " packets , size = " + str(size_packets)+" bytes\n")
		file1.close()
		file2.close()
		ip_count = {}

t1=threading.Thread(target=main)
t2=threading.Thread(target=output)
t1.start()
t2.start()
