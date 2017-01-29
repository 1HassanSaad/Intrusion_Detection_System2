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
def GetData():
    global in_out,src_ip,src_port,dest_ip,dest_port,proto,action;
    in_out = raw_input("in press 1 , out press 2 , to disable press 0 : ");
    src_ip = raw_input("source ip : ");
    src_port = raw_input("source port : ");
    if(src_port==""):
        src_port='0';
    dest_ip = raw_input("destination ip : ");
    dest_port = raw_input("destination port : ");
    proto = raw_input("protocol -> 0 means all , 1 means tcp , 2 means udp : ");
    action = raw_input("for block press 0 , for unblock press 1 : ");
print "Hello in our firewall ...";
option = raw_input("Enter the Option you seek: 1-add , 2 -delete , 3 -show");
if(option=='1'):
    GetData();
    convertSrc_ip = str(IpConverter(src_ip)); 
    convertDest_ip = str(IpConverter(dest_ip));
    f = open('firee.txt','a');
    f.write(in_out+','+convertSrc_ip+','+src_port+','+convertDest_ip+','+dest_port+','+proto+','+action+','+'\n');
    f.close()
if(option=='2'):
    GetData();
    convertSrc_ip = str(IpConverter(src_ip)); 
    convertDest_ip = str(IpConverter(dest_ip));
    S=in_out+','+convertSrc_ip+','+src_port+','+convertDest_ip+','+dest_port+','+proto+','+action+','+'\n';
    f = open("firee.txt","r");
    lines = f.readlines()
    f.close()
    f = open("firee.txt","w");
    for line in lines:
        if line!=S:
            f.write(line)
    f.close()
