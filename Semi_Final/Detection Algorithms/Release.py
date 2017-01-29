import MySQLdb,os
import threading,datetime,time


def CmpTime(TTR):
	releaseT = str(TTR)
	year = releaseT[0:4]
	month = releaseT[5:7]
	day = releaseT[8:10]
	hour = releaseT[11:13]
	minute = releaseT[14:16]

	x=datetime.datetime.now()
	Cyear = str(x.year)
	Cmonth = str(x.month)
	Cday = str(x.day)
	Chour = str(x.hour)
	Cminute = str(x.minute)
	
	if(Cyear > year):
		return 1
	if(Cyear == year):
		if(Cmonth > month):
			return 1
		if(Cmonth == month):
			if(Cday > day):
				return 1
			if(Cday == day):
				if(Chour > hour):
					return 1
				if(Chour == hour):
					if(Cminute >= minute):
						return 1
	return 0

db = MySQLdb.connect(host="localhost",user="root",passwd="",db="Firewall")
query = db.cursor()
src = "116.13.56.12"
query.execute("SELECT TTR,IP FROM blacklist")
TTR = query.fetchall()
for i in range (0,TTR.__len__()):
	Flag_Rel = CmpTime(TTR[i][0])
	if Flag_Rel == 1:
		query.execute("DELETE FROM input WHERE RSrc_IP=%s ",[TTR[i][1]])
		db.commit()
query.execute("SELECT Src_IP,Dest_IP FROM input")
Data = query.fetchall()
rules = open("firee.txt","w+")
for i in range (0,Data.__len__()):
	src_ip = Data[i][0]
	dest_ip = Data[i][1] 
	rule = "1," + str(src_ip) + ",0," + str(dest_ip) + ",0,0,0,\n"
	rules.write(rule)

rules.close()
os.system("bash fire.sh")
db.close()
