# Asterisk AMI Scanner, for more Commands to add, look in the CLI under ' manager show command '
# Quick and Dirty tool 

import sys, os, re, telnetlib, time, pymysql,json, daemon
from multiprocessing import Process, Pipe, Queue


#Asterisk user Data
user = '' ## your User 
pw = '' # User PW


#Mysql data
mysql_user = '' #mysql user
mysql_pw = '' #Mysql passowrt
mysql_db = 'Asterisk_blocklist' #Mysql database
mysql_host = 'localhost' #Mysql host

homepath = '/net/html/asterconf/' # Write here your Path 


def telnet_runner (tel_in,tel_out,user,pw):#Telnet Runner Process
    a = True
    login_data = 'Action: Login' # Set on Standart Log on
    login_data1 = "Username: " + user 
    login_data2 = "Secret: " + pw 

    
    
    #print (login_data)
    tel_con = telnetlib.Telnet() #add function
    tel_con.open('127.0.0.1','5038') #start Telnet
    b = tel_con.read_very_eager() #first read
    tel_con.write(login_data.encode('ascii') + b'\r\n') #log on 
    tel_con.write(login_data1.encode('ascii') + b'\r\n')
    tel_con.write(login_data2.encode('ascii')  + b'\r\n')
    tel_con.write(b'\r\n') #Enter all data (SCREW YOU)
    while a == True:# main Telnet while
        
        time.sleep(0.1) #save CPU 
        while tel_in.qsize() != 0: #check incoming data from the Main Thread
            write_data = tel_in.get() #get data
            if write_data == 'end': #End, Close programm 
                pw = 'end'
            else:
                tel_con.write(write_data.encode('ascii') + b'\r\n') #code send to Asterisk 
        try:
            b = tel_con.read_very_eager()#read Telnet
        except EOFError: #when Connection Broken conneckt 
            tel_con.open('127.0.0.1','5038')
        
            tel_con.write(login_data.encode('ascii') + b'\r\n')
            tel_con.write(login_data1.encode('ascii') + b'\r\n')
            tel_con.write(login_data2.encode('ascii')  + b'\r\n')
            tel_con.write(b'\r\n')
        
        c = 0
        ret_var = ''
        create = {}
        if b != b'':
            ret_var = {}
            d = b.decode('utf8')#convert Byte to UTF8
            
            for x in d.splitlines():#split in lines 
                if x == '': #check parting line and create new Data Block
                    c = c +1
                    print(len(create)) 
                    if len(create) != 0:
                        #print('create')
                        #print(create)
                        ret_var[c] = {} #Create Send Dictanary for the main Thread
                        ret_var[c] = create #Create new sub Dictonary
                        create = {}
                    

                else:#Fill data in dict
                    k = x.split(': ',1)
                    create[k[0]] = k[1] 
                    
        if ret_var != '': #send data to Main thread
            #print (ret_var)
            tel_out.put(ret_var)

        if pw == 'end': #Kill Thread
            tel_con.close()
            tel_out.put('end')
            a = False
            
            
def mysql_insert (db_con,db,data_dic): #Insert data in Mysql und Block IP 
    db_cur = db_con.cursor()
    c = 0 
    spalte = ''
    values = ''
    for x in data_dic: #setting comma
        if c != 0:
            spalte += ', '
            values += ', '
        
        c = c + 1
        spalte += '`'+ x + '`'
        values += '\''+ data_dic[x]  +'\'' #add data 
        
   
    sql = "SELECT `ip`, `id`, `count` FROM `"+db+"` WHERE `ip`='"+data_dic['ip']+"'" #try to read older data
    db_cur.execute(sql) #execute
    result = ''
    result = db_cur.fetchone()
            
    try: 
        a = len(result)
    except TypeError:
        result = ''
    
    if result == '': #insert new entry
        sql_insert = "INSERT INTO `blocklist` ("+spalte+") VALUES ("+values+")"
    else: #Update data
        sql_insert = "UPDATE `"+db+"` SET `count` = count + 1, `complete` = '"+data_dic['complete']+"' WHERE `blocklist`.`id` = "+str(result['id'])+""
        if int(result['count']) > 4: #after 5 trys, IP got Blockt
            sp = data_dic['ip'].split('.')
            if sp[0] != '192':#Ignore Home IP 
                os.system('iptables -A INPUT -s '+ data_dic['ip'] +' -j DROP ') #Add IP to Filter 
            
                #iptables -A INPUT -s 10.0.0.1 -j DROP   # Input in IP tables
                #iptables -D INPUT -s 10.0.0.1 -j DROP   # Delete from IP tables
                #iptables -L                             # List all Drops 


    db_cur.execute(sql_insert)#Upate Mysql 
    db_con.commit()
    
    #print(sql_insert)


    

def main_program():#Main Loop
    
    mysql_connection = pymysql.connect(host=mysql_host,
                             user=mysql_user,
                             password=mysql_pw,
                             database=mysql_db,
                             charset='utf8mb4',
                             cursorclass=pymysql.cursors.DictCursor) #Mysql Connekt


    a = True #main While Control
    data = ''
    tel_in = Queue() #Telnet runnter queue
    tel_out = Queue() #Telnet runnter queue
    p = Process(target=telnet_runner, args=(tel_out,tel_in,user,pw)) #own Prozess
    p.start()
    count = 0
    while a == True: #Main Loop
        #count = count + 1 self Kill Control 
        time.sleep(0.1)
        while tel_in.qsize() != 0:#get data from Telnet runner
            data = tel_in.get()

        #if count > 1000: # Self kill 
            #tel_out.put('end') self kill

        if data == 'end':#End Programm
            p.close()
            a = False
            p.close()
            data= ''
            
        
        if data != '': #check data from Telnet Runner
            
            for x in data:

                if 'Event' in  data[x]:
                        
                    if data[x]['Event'] == 'InvalidAccountID': #if wrong Login
                        cc=''
                        for y in data[x]:#all data in one line 
                            cc += "" + y + " -->" + data[x][y] + "||"
                   
                        ip_sp = data[x]['RemoteAddress'].split('/')#gettinh only the IP 
                        db_ins_dic = {'ip': ip_sp[2],'count': '1','complete': cc}
                        mysql_insert(mysql_connection,'blocklist',db_ins_dic) # send data an mysql 
                    
                
                
            
            data= ''#clear all data
    



if __name__ == '__main__':#start Daemon
    
    context = daemon.DaemonContext( #daemon konfig
    	working_directory= homepath ,
       	umask=0o002,

    )
    with context:
        main_program()
