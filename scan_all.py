#!/usr/bin/python
import pymysql
from scapy.layers.inet import *
from scapy.all import *

"""
conex1 = pymysql.Connect(user='victor', password='victor', host='127.0.0.1', database='REDES')
cursor = conex1.cursor()
cursor.execute("SELECT IP FROM REDES.HOSTS;")
resultados_tcp=cursor.fetchall()

cursor.close()
conex1.close()
"""
resultados_tcp=['192.168.10.91','192.168.10.92']
ip_puertos_open=dict()
puertos=[]
for x in resultados_tcp:

#host = '192.168.10.2'
#portRange = [22, 80, 445, 902, 139]
# omprueba que el host tenga ping
    respHost = sr1(IP(dst=x)/ICMP(), timeout=2, verbose=0)
    if respHost is None:
        print("Host %s off"%x)

    #SI LA IP 192.168.10.93 ESTA UP ENTRA EN EL ELSE

    else:
        ip_puertos_open.setdefault(x)

        #RECORRE LOS PUERTOS DEL 1 AL 22 DE LA IP 192.168.10.93
        for port in range(1,112):

            resp = sr1(IP(dst=x) / TCP(dport=port, flags="S"), timeout=1, verbose=0)

            try:
                if resp.haslayer(TCP):
                    if (resp.getlayer(TCP).flags == 0x12):#SYN-ACK SA
                        # Send a gratuitous RST to close the connection
                        send_rst = sr(IP(dst=x) / TCP(dport=port, flags='R'), timeout=1, verbose=0)
                        # CADA PUERTO OPEN SE ADD AL DICC
                        puertos.append(port)
                        ip_puertos_open[x] = puertos

            except AttributeError:
                pass
        puertos=[]#reset variable a 0 volver add nuevos puertos a cada ip

print(ip_puertos_open)

