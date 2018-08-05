import socket
import sys
import pandas as pd
import cPickle as pc
from threading import Thread 
import time
import threading
lock = threading.Lock()
neighbours={ 'h1':[('r1','192.0.1.2')],
             'h2':[('r4','197.1.1.2')],
	     'r1':[('h1','192.0.1.1'),('r2','193.0.1.2'),('r3','194.0.1.2')],
	     'r2':[('r1','192.0.1.2'),('r4','197.1.1.2')],
             'r3':[('r1','192.0.1.2'),('r4','197.1.1.2')],
	     'r4':[('h2','197.1.1.1'),('r2','193.0.1.2'),('r3','194.0.1.2')] }
ip_addr_self={'h1':'192.0.1.1',
        'h2':'197.1.1.1',
	'r1':'192.0.1.2',
	'r2':'193.0.1.2',
	'r3':'194.0.1.2',
	'r4':'197.1.1.2'
	}
class ServerThread_Node(Thread):
	def __init__(self,conn,host): 
        	Thread.__init__(self) 
		self.conn=conn
		self.host=host
		
	def run(self):
		global lock	 
		converged = False
		lock.acquire()
		old_routing_tab= pd.read_csv(str(self.host)+'.csv')
		lock.release()
		old_tab_obj=pc.dumps(old_routing_tab)
		self.conn.send(old_tab_obj)
		
		while True :
			lock.acquire()
			new_routing_tab= pd.read_csv(str(self.host)+'.csv')
			if new_routing_tab.equals(old_routing_tab):
				counter+=1
				if counter==150:
					coverged=True
					#Converged File logic
			#		convg_tab = pd.read_csv('converged.csv')
			#		convg_tab.loc[routing_tab["Nodes"]=="", "Value"] = True						
			else:
				old_routing_tab=new_routing_tab
				counter=0
				converged=False
				new_tab_obj=pc.dumps(new_routing_tab)
				self.conn.send(new_tab_obj)
			lock.release()            
class Server(Thread):
	def __init__(self,ip_addr1,host): 
        	Thread.__init__(self) 
        	self.ip1= ip_addr1
		self.port=12345
		self.host=host
		self.server1= socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
		self.server1.bind((self.ip1,self.port)) 

	def run(self): 
        	while True : 
			self.server1.listen(3)
			(conn, (ip,port_conn)) = self.server1.accept() 
			newthread =ServerThread_Node(conn,self.host) 
			newthread.start() 
		
			
class Client(Thread):
	def __init__(self,name,ip,hostname): 
       		Thread.__init__(self) 
		self.name=name
		self.clientname=hostname
		self.ip=ip
		self.port=12345
		self.client1=socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
		self.client1.connect((self.ip,self.port))

	def run(self):
		global lock
		while True:
			obj_bytes=self.client1.recv(4096)
			# Data Frame From Server
			server_data_obj=pc.loads(obj_bytes)
			
			server_data_obj_nodes = server_data_obj["Nodes"].tolist()
			server_data_obj_distances=map(int,server_data_obj["Distance"].tolist())
			server_data_obj_nexthop=server_data_obj["NextHop"].tolist()
			
			#Data Frame of Client
			lock.acquire()
			client_node_tab=pd.read_csv(str(self.clientname)+'.csv')
			client_data_obj_nodes = client_node_tab["Nodes"].tolist()
			client_data_obj_distances=map(int,client_node_tab["Distance"].tolist())
			client_data_obj_nexthop=client_node_tab["NextHop"].tolist()
			
			distance_row=client_node_tab[client_node_tab['Nodes'] == str(self.name)]
			distance_r = int(distance_row.iloc[0]['Distance'])
					
			for i in range(len(client_data_obj_nodes)):
				if (client_data_obj_nexthop[i]==self.name) or (server_data_obj_distances[i]+distance_r < client_data_obj_distances[i]):
					client_data_obj_nexthop[i]=self.name
	 				client_data_obj_distances[i]= server_data_obj_distances[i]+distance_r
			client_routing_tab_new=pd.DataFrame.from_items([('Nodes',client_data_obj_nodes), ('Distance',client_data_obj_distances),('NextHop',client_data_obj_nexthop)])
			client_routing_tab_new.to_csv(str(self.clientname)+'.csv',index=False)
			lock.release()
			
host= sys.argv[1]
ip_addr=ip_addr_self[host[1:]]
list1=neighbours[host[1:]]
s=Server(ip_addr,host[1:])
s.start()
time.sleep(5)
for x in list1:
	c=Client(x[0],x[1],host[1:])
	c.start()
	time.sleep(0.4)


