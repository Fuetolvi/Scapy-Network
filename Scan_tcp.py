#!/usr/bin/python
import pymysql
from scapy.layers.inet import *



conex1 = pymysql.Connect(user='victor', password='victor', host='127.0.0.1', database='REDES')
cursor = conex1.cursor()
cursor.execute("SELECT HOSTS.IP,TCP.PUERTO,STATUS.SITUACION FROM STATUS JOIN HOSTS ON HOSTS.id_IP=STATUS.id_IP JOIN TCP ON TCP.idTCP = STATUS.idTCP;")
resultados_tcp=cursor.fetchall()

cursor.close()
conex1.close()

#for x in resultados_tcp:

host = '192.168.10.91'
port=[1,22,80,144]
#portRange = [22, 80, 445, 902, 139]
"""Comprueba que el host tenga ping"""
respHost = sr1(IP(dst=host)/ICMP(), timeout=1, verbose=0)
if respHost is None:
        print("Host %s off"%host)


else:

    # Send SYN with random Src Port for each Dst port
    #x[0] es cada ip
    for p in port:

        resp = sr1(IP(dst=host) / TCP(dport=p, flags="S"), timeout=1, verbose=0)


        if resp is None:
            print('{}:{} is filtered (silently dropped).'.format(host, str(p)))


        elif (resp.haslayer(TCP)):
            if (resp.getlayer(TCP).flags == 0x12):#SYN-ACK SA
                # Send a gratuitous RST to close the connection
                send_rst = sr(IP(dst=host) / TCP(dport=p, flags='R'), timeout=1, verbose=0)
                print('{}:{} is open.'.format(host, str(p)))


            elif (resp.getlayer(TCP).flags == 0x14):# RA
                    print('{}:{} is closed.'.format(host, str(p)))





