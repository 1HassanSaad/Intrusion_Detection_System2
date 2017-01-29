import MySQLdb
import threading,datetime,time

db = MySQLdb.connect(host="localhost",user="root",passwd="",db="Firewall")
query = db.cursor()
src_ip ="192.168.1.7"
#dest_ip = "192.167.54.54"
#src = "412341"
#dest = "12321"
x = datetime.datetime.now();
time = str(x.year)+":"+str(x.month)+":"+str(x.day+3)+":"+str(x.hour+3)+":"+str(x.minute)+":"+str(x.second)
src = "116.13.55.16"
Attacked = 3
#query.execute ("UPDATE blacklist SET TTR= %s,Attacked= %s WHERE IP= %s",[time,Attacked,src])
#db.commit()
query.execute("INSERT INTO blacklist (IP,TTR) VALUES (%s,%s)",[src,time])
db.commit()
#query.execute("SELECT Attacked FROM blacklist WHERE IP = %s",[src])
#InBlack = query.rowcount
#Attacked_Number = query.fetchone();
#print Attacked_Number[0]

#quary.execute("INSERT INTO input (Src_IP, Dest_IP, RSrc_IP, RDest_IP , AttackTime) VALUES (%s,%s,%s,%s,%s)",[src_ip,dest_ip,src,dest,x] )
#db.commit()
db.close()
