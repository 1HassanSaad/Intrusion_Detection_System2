from LIB import sniffer,get_local_ip
import threading,datetime,time

Attacker_with_users = {}
Attacker_without_users = {}
FTP_USER = ""
FTP_PASS = ""
EROR_MSG = ""
LOCAL_IP = get_local_ip()

def main():
	global FTP_USER,FTP_PASS,EROR_MSG,Attacker_with_users,Attacker_without_users
	while(True):
		retn_data = sniffer()
		if retn_data['proto'] == "TCP" :
			if retn_data['dst_port'] == 21 and retn_data['dst_ip'] == LOCAL_IP and retn_data['pure_data'].upper().find("USER ") >= 0 :
				index1 = retn_data['pure_data'].upper().find("USER")
				index2 = retn_data['pure_data'].upper()[index1:].find(" ")
				FTP_USER = retn_data['pure_data'][index1+index2+1:]
				
			if FTP_USER:	
				if retn_data['dst_port'] == 21 and retn_data['dst_ip'] == LOCAL_IP and retn_data['pure_data'].upper().find("PASS ") >= 0 :
					FTP_PASS = "FOUND"
						
			if FTP_USER and FTP_PASS:
				if retn_data['src_port'] == 21 and retn_data['src_ip'] == LOCAL_IP and retn_data['pure_data'].upper().find("LOGIN INCORRECT") >= 0 :
					EROR_MSG = "FOUND"
						
			if FTP_USER and FTP_PASS and EROR_MSG :
				ip = retn_data['dst_ip']
				TheKey = str(ip+"@"+FTP_USER)  #the attacker's IP
				FTP_USER = ""
				FTP_PASS = ""
				EROR_MSG = ""
				if Attacker_with_users.has_key(TheKey):
					Attacker_with_users[TheKey] += 1
				else:
					Attacker_with_users[TheKey] = 1	
					
				if Attacker_without_users.has_key(ip):
					Attacker_without_users[ip] += 1
				else:
					Attacker_without_users[ip] = 1

def output():
	global Attacker_with_users,Attacker_without_users
	while(True):
		file1 = open("Detection Algorithms/FTP_details","a")
		x=datetime.datetime.now()
		file1.write("data="+str(x.year)+":"+str(x.month)+":"+str(x.day)+":"+str(x.hour)+":"+str(x.minute)+":"+str(x.second)+"\n")
		file1.close()
		time.sleep(30)
		file1 = open("Detection Algorithms/FTP_details","a")
		file2 = open("Detection Algorithms/ATTACK_details","a")
		for ip,num in Attacker_with_users.iteritems():
			file1.write(ip + " num of trying = " + str(num)+"\n")
		
		for ip,num in Attacker_without_users.iteritems():	
			if num > 10:
				file2.write(str(ip) + " FTP Brute Force Attack , "+"data="+str(x.year)+":"+str(x.month)+":"+str(x.day)+":"+str(x.hour)+":"+str(x.minute)+":"+str(x.second)+"\n" )
				print str(ip) + " FTP Brute Force Attack , "+"data="+str(x.year)+":"+str(x.month)+":"+str(x.day)+":"+str(x.hour)+":"+str(x.minute)+":"+str(x.second)+"\n"
		file1.close()
		file2.close()
		Attacker_with_users = {}
		Attacker_without_users = {}
		
t1=threading.Thread(target=main)
t2=threading.Thread(target=output)
t1.start()
t2.start()

