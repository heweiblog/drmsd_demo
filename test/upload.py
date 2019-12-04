#!/usr/bin/python3
# -*- coding: utf-8 -*-  
import os, sys, re, time, datetime, gzip, paramiko, json, traceback
import codecs

def upload_to_ftp(file_name,data_type):
	ftp_ip, ftp_port, ftp_user, ftp_pwd, ftp_dir = '192.168.65.122',22,'shanghai','test123','/upload/xxx'
	
	dir_list = []
	if ftp_dir.find('/') >= 0:
		dir_list = ftp_dir.split('/')
		del(dir_list[0])
	else:
		dir_list = [ftp_dir]
	print(dir_list)
	try:
		transport = paramiko.Transport((ftp_ip, ftp_port))
		transport.connect(username = ftp_user, password = ftp_pwd)
		sftp = paramiko.SFTPClient.from_transport(transport)
		listdir = sftp.listdir('/')
		print('/')
		for i in dir_list:
			if i not in listdir:
				sftp.mkdir(i)
				print('ftp upload dir not exit and create',i)
			sftp.chdir(i)
			listdir = sftp.listdir('.')
		#if ftp_dir not in listdir:
			#ftp.mkdir(ftp_dir)
			#print('ftp upload dir not exit and create')
		#sftp.chdir(ftp_dir)
		print(ftp_dir)
		listdir = sftp.listdir('.')
		if data_type not in listdir:
			sftp.mkdir(data_type)
		sftp.chdir(data_type)
		print(data_type)
		listdir = sftp.listdir('.')
		data_dir = time.strftime('%Y-%m-%d')
		if data_dir not in listdir:
			sftp.mkdir(data_dir)
		sftp.chdir(data_dir)
		print(data_dir)
		sftp.put('/tmp/'+file_name,file_name)
	
	except Exception as r:
		print('r=',r,type(r))
		e = traceback.print_exc()
		print(type(e),e)
	print('success')
	return True


def upload_root_data(querys,respond,noerror):
	operator, vendor, node_id, server_id, upload_delay = 'ct','yamu','shanghai01','xuhui01',300
	root_resove_data = {
		'operator': operator,
		'vendor' : vendor,
		"timestamp" : time.strftime('%Y-%m-%d %H:%M:%S'),
		"data" : {
			'id': node_id,
			'server-id': server_id,
			'begin-date': (datetime.datetime.now() - datetime.timedelta(minutes=5)).strftime('%Y-%m-%d %H:%M:%S'), 
			'end-date': time.strftime('%Y-%m-%d %H:%M:%S'),
			'qps': querys/upload_delay,
			'update-date': time.strftime('%Y-%m-%d %H:%M:%S'),
			'resolution-count': respond,
			'response-success-rate': '100%' if querys == 0 else str(respond*100/querys)+'%',
			'resolution-success-rate': '100%' if querys == 0 else str(noerror*100/querys)+'%',
			'delay': 50,
			'top10': ['com','net','cn','org','gov','edu','top','mil','vip','int'] 
		}
	}
	
	file_name = 'zoneQuery' + '_' + operator + '_' + vendor + '_' + time.strftime('%Y-%m-%d-%H-%M-%S') + '.gz'
	with gzip.open('/tmp/' + file_name, "wb") as f:
		data = json.dump(root_resove_data, f, sort_keys=True, indent=4, separators=(',', ': '))
	
	upload_to_ftp('/tpm/'+file_name,'16')

def upload_recursion_data(querys,respond,noerror):
	operator, vendor, node_id, server_id, upload_delay = 'ct','yamu','shanghai01','xuhui01',300
	recursion_resove_data = {
		'operator': operator,
		'vendor' : vendor,
		'timestamp' : time.strftime('%Y-%m-%d %H:%M:%S'),
		'data' : {
			'id': node_id,
			'server-id': server_id,
			'begin-date': (datetime.datetime.now() - datetime.timedelta(minutes=5)).strftime('%Y-%m-%d %H:%M:%S'), 
			'end-date': time.strftime('%Y-%m-%d %H:%M:%S'),
			'qps': querys/upload_delay,
			'update-date': time.strftime('%Y-%m-%d %H:%M:%S'),
			'resolution-count': respond,
			'response-success-rate': '100%' if querys == 0 else str(respond*100/querys)+'%',
			'resolution-success-rate': '100%' if querys == 0 else str(noerror*100/querys)+'%',
			'resolution-count-v4': 2233, #get_ipv4()
			'resolution-count-v6': 1122, #get_ipv6()
			'query-7706-count': 1122, 
			'query-7706-count': 101,
			'query-root-count': {'的方法':12,'f':25},
			'query-root-delay': {'e':1000,'a':2000},
			'delay': 50
		}
	}

	#xml test
	import xmltodict
	print(len(recursion_resove_data))
	d = {'data':recursion_resove_data}
	xml = xmltodict.unparse(d)
	print(xml)
	print(type(xml))
	from xml.dom import minidom
	xml = minidom.parseString(xml).toprettyxml(indent="\t")
	print(type(xml))

	file_name = 'zoneQueryInfo_full_' + server_id + '_0_' + time.strftime('%Y%m%d%H%M%S') + '.gz'
	if len(file_name) > 0:
		try:
			with gzip.open('/tmp/'+file_name, "wb") as f:
				d = {'zoneQueryInfo' : recursion_resove_data}
				data = minidom.parseString(xmltodict.unparse(d)).toprettyxml(indent="\t")
				f.write(bytes(data, 'utf-8'))
			upload_to_ftp(file_name,'16')
			#os.remove('/tmp/' + file_name)
		except Exception as e:
			logger.error('upload root resove data error:'+str(e))

	#with open('demo.xml','w') as f:
		#f.write(xml)

	'''
	#d = json.dumps(recursion_resove_data)
	d = json.dumps(recursion_resove_data,ensure_ascii=False,indent=4)
	import socket
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect(('192.168.5.41', 9999))
	print(d)
	s.send(bytes(d, 'utf-8'))
	file_name = 'dnsQuery' + '_' + operator + '_' + vendor + '_' + time.strftime('%Y-%m-%d-%H-%M-%S') + '.gz'
	with gzip.open('/tmp/' + file_name, "wb") as f:
		data = json.dumps(recursion_resove_data,ensure_ascii=False,indent=4)
		f.write(bytes(data, 'utf-8'))
		#data = json.dump(recursion_resove_data, f,ensure_ascii=False, sort_keys=True, indent=4, separators=(',', ': '),)
	
	upload_to_ftp(file_name,'14')
	print('/tmp/' + file_name)
	#os.remove('/tmp/' + file_name)
	'''
	
upload_recursion_data(3000,2900,2500)
#upload_root_data(3000,2900,2500)
