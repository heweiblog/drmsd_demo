#!/usr/bin/python3
# -*- coding: utf-8 -*-

from __future__ import print_function

import os, sys, re, time, datetime, logging, random, string, logging.handlers, gzip, paramiko
import multiprocessing, subprocess, requests, urllib3, uuid
from threading import Timer
from configparser import ConfigParser
from Crypto.Cipher import AES

from iscpy.iscpy_dns.named_importer_lib import *
import base64, hashlib, zlib, json, lxml.etree, pexpect, dns, dns.resolver

from time import sleep
import threading, binascii, xml.dom.minidom, shutil, xmltodict

from spyne import ServiceBase
from spyne.protocol.soap import Soap11
from spyne.decorator import rpc
from spyne.model.primitive import Integer, Int, Long, Unicode
from spyne.model.complex import Iterable
from spyne.application import Application
#from spyne.server.wsgi import WsgiApplication
from spyne.util.wsgi_wrapper import WsgiMounter
from spyne.util.etreeconv import root_etree_to_dict
from wsgiref.simple_server import make_server

import osa, daemon

waj_conf = {}

root_all_ip_list = [
	'202.12.27.33','2001:dc3::35',
	'199.9.14.201','2001:500:200::b',
	'192.33.4.12','2001:500:2::c',
	'199.7.91.13','2001:500:2d::d',
	'192.203.230.10','2001:500:a8::e',
	'192.5.5.241','2001:500:2f::f',
	'192.112.36.4','2001:500:12::d0d',
	'198.97.190.53','2001:500:1::53',
	'198.41.0.4','2001:503:ba3e::2:30',
	'192.36.148.17','2001:7fe::53',
	'192.58.128.30','2001:503:c27::2:30',
	'193.0.14.129','2001:7fd::1',
	'199.7.83.42','2001:500:9f::42'
] 

root_all_list = {
	'm': ['202.12.27.33','2001:dc3::35'],
	'b': ['199.9.14.201','2001:500:200::b'],
	'c': ['192.33.4.12','2001:500:2::c'],
	'd': ['199.7.91.13','2001:500:2d::d'],
	'e': ['192.203.230.10','2001:500:a8::e'],
	'f': ['192.5.5.241','2001:500:2f::f'],
	'g': ['192.112.36.4','2001:500:12::d0d'],
	'h': ['198.97.190.53','2001:500:1::53'],
	'a': ['198.41.0.4','2001:503:ba3e::2:30'],
	'i': ['192.36.148.17','2001:7fe::53'],
	'j': ['192.58.128.30','2001:503:c27::2:30'],
	'k': ['193.0.14.129','2001:7fd::1'],
	'l': ['199.7.83.42','2001:500:9f::42']
}

class AESCipher:
	def __init__(self, key, iv):
		self.key = key 
		self.iv = iv 
	def __pad(self, text):
		text_length = len(text)
		amount_to_pad = AES.block_size - (text_length % AES.block_size)
		if amount_to_pad == 0:
			amount_to_pad = AES.block_size
		pad = chr(amount_to_pad)
		return text + (pad * amount_to_pad).encode('utf-8')
	def __unpad(self, text):
		pad = text[-1] #ord(text[-1])
		return text[:-pad]
	def encrypt(self, raw):
		raw = self.__pad(raw)
		cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
		return cipher.encrypt(raw)
	def decrypt(self, enc):
		cipher = AES.new(self.key, AES.MODE_CBC, self.iv )
		return self.__unpad(cipher.decrypt(enc))#.decode("utf-8"))

def getXmlValue(dom, root, xpath):
	ml = dom.getElementsByTagName(root)[0]
	node = ml.getElementsByTagName(xpath)[0]
	for n in node.childNodes:
		nodeValue = n.nodeValue
		return nodeValue
	return None


def gen_commandack_result(dnsId, cmdId, cmdType, resultCode):
	xml = u'''\
<?xml version="1.0" encoding="UTF-8"?>
<dnsCommandAck>
    <dnsId>%s</dnsId>
    <commandAck>
        <commandId>%s</commandId>
        <type>%d</type>
        <resultCode>%d</resultCode>
        <appealContent></appealContent>
        <msgInfo></msgInfo>
    </commandAck>
    <timeStamp>%s</timeStamp>
</dnsCommandAck>
''' % (dnsId, cmdId, cmdType, resultCode, time.strftime('%Y-%m-%d %H:%M:%S'))
    
	return xml


def dnsCommandAck(commandType, commandSequence, dnsId, hashAlgorithm, compressionFormat, encryptAlgorithm, resultCode):
	global gPwd, gAESKey, gAESIV, ackhost, ackport, logger

	sleep(1) 
	result = bytes(gen_commandack_result(dnsId, commandSequence, commandType, 0 if resultCode==0 else 2), encoding = 'utf-8')
	randVal = bytes(''.join(random.sample(string.ascii_letters, 20)), 'utf-8')
	lPwd = bytes(gPwd,'utf-8')

	if hashAlgorithm == 0: 
		_hashed_pwd = lPwd + randVal
		pwdHash = base64.b64encode(_hashed_pwd)
	elif hashAlgorithm == 1: 
		_hashed_pwd = hashlib.md5(lPwd + randVal).digest()
		pwdHash = base64.b64encode(binascii.b2a_hex(_hashed_pwd))
	elif hashAlgorithm == 2: 
		_hashed_pwd = hashlib.sha1(lPwd + randVal).digest()
		pwdHash = base64.b64encode(binascii.b2a_hex(_hashed_pwd))

	if compressionFormat == 0: _compressed_result = result
	elif compressionFormat == 1: _compressed_result = zlib.compress(result)

	e = AESCipher(gAESKey, gAESIV)
	if (gAESKey is not None) and (encryptAlgorithm == 1): 
		_encrypted_result = e.encrypt(_compressed_result)
	else: _encrypted_result = _compressed_result
    
	result = base64.b64encode(_encrypted_result)

	if hashAlgorithm == 0: 
		_hashed_result = _compressed_result + lPwd
		resultHash = base64.b64encode(_hashed_result)
	elif hashAlgorithm == 1: 
		_hashed_result = hashlib.md5(_compressed_result + lPwd).digest()
		resultHash = base64.b64encode(binascii.b2a_hex(_hashed_result))
	elif hashAlgorithm == 2: 
		_hashed_result = hashlib.sha1(_compressed_result + lPwd).digest()
		resultHash = base64.b64encode(binascii.b2a_hex(_hashed_result))

	commandVersion = 'v0.1'

	cl = osa.Client('http://%s:%d/DNSWebService/dnsCommandAck?wsdl' % (ackhost, ackport))
    
	try:
		r = cl.service.dns_commandack(dnsId, str(randVal, encoding='utf-8'), 
		str(pwdHash,encoding='utf-8'), str(result,encoding = 'utf-8'),
		str(resultHash,encoding='utf-8'), encryptAlgorithm, hashAlgorithm,compressionFormat, commandVersion)

		dom = xml.dom.minidom.parseString(r)
		res = int(getXmlValue(dom, "return", "resultCode"))
		logger.info('return to drms dnsCommandAck result_code {}'.format(res))

		if res == 0:
			logger.info('return to drms dnsCommandAck success')
		else:
			logger.error('return to drms dnsCommandAck failed')

	except Exception as e:
		logger.warning('dnsCommandAck exception:'+str(e))
		l = str(e).split('/')
		if 'tmp' in l:
			d = '/tmp/' + l[-2]
			if os.path.exists(d) == False:
				os.mkdir(d)
				logger.info('mkdir '+d+' and copy /var/drmsd_data/base_library.zip')
				shutil.copyfile('/var/drmsd_data/base_library.zip',d+'/base_library.zip')

			r = cl.service.dns_commandack(dnsId, str(randVal, encoding='utf-8'), 
			str(pwdHash,encoding='utf-8'), str(result,encoding = 'utf-8'),
			str(resultHash,encoding='utf-8'), encryptAlgorithm, hashAlgorithm,compressionFormat, commandVersion)

			dom = xml.dom.minidom.parseString(r)
			res = int(getXmlValue(dom, "return", "resultCode"))
			logger.info('return to drms dnsCommandAck result_code {}'.format(res))

			if res == 0:
				logger.info('return to drms dnsCommandAck success')
			else:
				logger.error('return to drms dnsCommandAck failed')
		else:
			logger.warning('dnsCommandAck exception:'+str(e))
			return -1


def genResult(rcode, commandType, commandId, dnsId, hashAlgorithm, compressionFormat, encryptAlgorithm):
	lookaside = {
		0 : 'Done',
		1 : 'De-cryption error',
		2 : 'Certification error',
		3 : 'De-compression error',
		4 : 'Invalid type',
		5 : 'Malformed content',
		900 : 'Other error, try again'                                                        
	}
    
	xml = u'''<?xml version="1.0" encoding="UTF-8"?>
	<return>
		<resultCode>%d</resultCode>
		<msg>%s</msg>
	</return>''' % (rcode, lookaside[rcode])
    
	if commandId:    
		threading._start_new_thread(dnsCommandAck, (commandType, commandId, dnsId, hashAlgorithm, compressionFormat, encryptAlgorithm, rcode))

	return xml


def certificate(pwdHash, randVal, hashAlgorithm):                                             
	global gPwd
	if hashAlgorithm == 0: 
		raw = gPwd + randVal 
		return pwdHash == base64.b64encode(raw.encode('utf-8')).decode('utf-8')
	elif hashAlgorithm == 1: raw = hashlib.md5((gPwd + randVal).encode()).digest()
	elif hashAlgorithm == 2: raw = hashlib.sha1((gPwd + randVal).encode()).digest()
	else: return False
	return pwdHash == base64.b64encode(binascii.b2a_hex(raw)).decode()


def aesDecode(raw):
	aes = AESCipher(gAESKey, gAESIV)
	return aes.decrypt(raw)


def deCMDPre(command, compressionFormat, commandHash, hashAlgorithm, encryptAlgorithm):
	global gAESKey, gPwd
	raw = base64.b64decode(command.encode('utf-8'))
	if (gAESKey is not None) and (encryptAlgorithm == 1):
		data = aesDecode(raw)
	else: data = raw
	if hashAlgorithm == 0: hashed = data + gPwd.encode('utf-8')
	elif hashAlgorithm == 1: hashed = hashlib.md5((data + gPwd.encode('utf-8'))).digest()
	elif hashAlgorithm == 2: hashed = hashlib.sha1((data + gPwd.encode('utf-8'))).digest()
	else: return None
	if hashAlgorithm == 0:
		if base64.b64encode(hashed).decode('utf-8') != commandHash:
			return None
	else:
		if base64.b64encode(binascii.b2a_hex(hashed)).decode('utf-8') != commandHash:
			return None
	if compressionFormat == 0: cmd = data
	elif compressionFormat == 1: cmd = zlib.decompress(data)
	return cmd


def xmlget(root, xpath):
	lst = root.xpath(xpath)
	if lst and lst[0].text:
		return lst[0].text
	return None


def switch_named_file(target,source):
	global home, rndc, logger

	if os.path.exists(home+"/"+target) == False:
		logger.error('[%d] file[%s] not exist error!' % os.getpid(),target)
		return False

	try:
		subprocess.check_call(['ln', '-f', '-s', target, source], cwd = home)
	except subprocess.CalledProcessError:
		logger.error('[%d] create link path error!' % os.getpid())
		return False

	try:
		subprocess.check_call([rndc, 'reconfig'], cwd = home)
	except subprocess.CalledProcessError:
		logger.error('[%d] rndc reconfig error!' % os.getpid())
		return False

	try:
		subprocess.check_call([rndc, 'flush'], cwd = home)
	except subprocess.CalledProcessError:
		logger.error('[%d] rndc flush error!' % os.getpid())
		return False

	logger.warn('[%d] root switch to `%s`' % (os.getpid(), target))
	return True


def upload_switch_result(target, dnsId, commandId):
	global node_id, zone_room_id, std, local, standard_source, exigency_source

	switch_data = dns_id + '|' + commandId + '|' + zone_room_id + '|' + node_id 

	if target == standard_source:
		switch_data += '|1|' + time.strftime('%Y-%m-%d %H:%M:%S') + '||' 
	elif target == std:
		switch_data += '|1|' + time.strftime('%Y-%m-%d %H:%M:%S') + '||' + time.strftime('%Y-%m-%d %H:%M:%S')
	elif target == exigency_source:
		switch_data += '|2|' + time.strftime('%Y-%m-%d %H:%M:%S') + '||' 
	elif target == local:
		switch_data += '|2|' + time.strftime('%Y-%m-%d %H:%M:%S') + '|' + time.strftime('%Y-%m-%d %H:%M:%S') + '|'

	file_name = 'zoneSwitch_diff_' + dns_id + '_' + commandId + '_' + time.strftime('%Y%m%d%H%M%S') + '.gz'

	logger.info(switch_data)
	
	try:
		with gzip.open('/var/drmsd_data/' + file_name, "wb") as f:
			f.write(bytes(switch_data, 'utf-8'))
		upload_to_ftp('/var/drmsd_data/',file_name,'17')
	except Exception as e:
		logger.error('upload root switch data error:'+str(e))


def switch_rootca(stdon, delay, dnsId, commandType, commandId, hashAlgorithm, compressionFormat, encryptAlgorithm):
	global std, local, logger, switch
	
	target = std if stdon else local
	if switch_named_file(target,switch):
		upload_switch_result(target, dnsId, commandId)
		return genResult(0, commandType, commandId, dnsId, hashAlgorithm, compressionFormat, encryptAlgorithm)
	return genResult(900, commandType, commandId, dnsId, hashAlgorithm, compressionFormat, encryptAlgorithm)


def switch_root_source(is_exigency, delay, dnsId, commandType, commandId, hashAlgorithm, compressionFormat, encryptAlgorithm):
	global standard_source, exigency_source, logger, root_source
	
	target = exigency_source if is_exigency else standard_source
	if switch_named_file(target,root_source):
		upload_switch_result(target, dnsId, commandId)
		return genResult(0, commandType, commandId, dnsId, hashAlgorithm, compressionFormat, encryptAlgorithm)
	return genResult(900, commandType, commandId, dnsId, hashAlgorithm, compressionFormat, encryptAlgorithm)


def respond18(cmd, commandType, dnsId, hashAlgorithm, compressionFormat, encryptAlgorithm):
	global logger

	ele = lxml.etree.fromstring(cmd)
	_commandId = xmlget(ele, 'commandId')
	_type = xmlget(ele, 'type')
	_urgency = xmlget(ele, 'urgency')
	_effectiveScope = xmlget(ele, 'range/effectiveScope')
	_check = xmlget(ele, 'privilege/check')
	_timestamp = xmlget(ele, 'timeStamp')
	_datasources = xmlget(ele, 'datasources')
	
	if _type != None:
		logger.info('switch root.ca type=%s' % _type)
		return switch_rootca(True if _type != '1' else False, 
			(2 * 60 * 60) if _urgency == '1' else (10 * 60), 
			dnsId, 8, _commandId, hashAlgorithm, 
			compressionFormat, encryptAlgorithm)

	if _datasources != None:
		logger.info('switch root source datasources=%s' % _datasources)
		return switch_root_source(True if _datasources != '1' else False, 
			(2 * 60 * 60) if _urgency == '1' else (10 * 60), 
			dnsId, 8, _commandId, hashAlgorithm, 
			compressionFormat, encryptAlgorithm)

	return genResult(900, commandType, _commandId, dnsId, hashAlgorithm, compressionFormat, encryptAlgorithm)


def respond19(cmd, commandType, dnsId, hashAlgorithm, compressionFormat, encryptAlgorithm):
	global upload_delay, logger

	ele = lxml.etree.fromstring(cmd)
	_commandId = xmlget(ele, 'commandId')
	_type = xmlget(ele, 'type')
	_timestamp = xmlget(ele, 'timeStamp')

	if _type == '1':
		share_delay.value = 900
		logger.info('sys switch to exigency status upload_delay {}'.format(int(share_delay.value)))
	if _type == '2':
		share_delay.value = 86400
		logger.info('sys switch to standard status upload_delay {}'.format(int(share_delay.value)))
	
	return genResult(0, 8, _commandId, dnsId, hashAlgorithm, compressionFormat, encryptAlgorithm)


class DRMSService(ServiceBase):
	@rpc(Unicode, Unicode, Unicode, Unicode, Unicode,Int, Long, Int, Int, 
		Int,Unicode, _out_variable_name = 'return', _returns = Unicode)

	def dns_command(ctx, dnsId, randVal, pwdHash, command, commandHash, commandType, 
	commandSequence, encryptAlgorithm, hashAlgorithm, compressionFormat, commandVersion):
		global logger
		try:
			if not certificate(pwdHash, randVal, hashAlgorithm):
				logger.error('certificate error')
				return genResult(2, commandType, None, dnsId, hashAlgorithm, compressionFormat, encryptAlgorithm) 
			cmd = deCMDPre(command, compressionFormat, commandHash,hashAlgorithm, encryptAlgorithm)
			if not cmd:
				logger.error("webService Malformed content do deCMDPre error")
				return genResult(5, commandType, None, dnsId, hashAlgorithm, compressionFormat, encryptAlgorithm)

			command_func = {18:respond18,19:respond19}
			if commandType in command_func:
				return command_func[commandType](cmd, commandType, dnsId, hashAlgorithm, compressionFormat, encryptAlgorithm)
		except Exception as e: 
			logger.error('command error:'+str(e))
			return genResult(900, commandType, None, dnsId, hashAlgorithm, compressionFormat, encryptAlgorithm)
        


def xgj_main_task():
	global listen_port

	application = Application([DRMSService],'http://webservice.ack.dns.act.com/', 
			in_protocol = Soap11(validator = 'lxml'), 
			out_protocol = Soap11())

	wsgi_app = WsgiMounter({'DNSWebService' : application})
	server = make_server('0.0.0.0', listen_port, wsgi_app)
	server.serve_forever()


def get_stat_file():
	global home, rndc, logger, stat_file, tmp_stat_file
	
	if os.path.exists(stat_file):
		os.remove(stat_file)
	if os.path.exists(tmp_stat_file):
		os.remove(tmp_stat_file)

	try:
		subprocess.call(['rndc','stats'])
		shutil.copy(stat_file,tmp_stat_file)
	except Exception as e:
		logger.error('rndc stats error:'+str(e))
		return False

	return True

def get_stat_data(stat_file):
	try:
		with open(stat_file,'r') as f:
			data = {}
			for line in f:
				if re.match('\+\+\+ ', line):
					match_time = re.search('[0-9]+', line)
					if match_time:
						time = match_time.group()
					else:
						time = 0
				elif re.match('--- ', line):
					pass
				elif re.match('\+\+ ', line):
					sub = re.sub(' ?\+\+ ?', '', line)
					sub = re.sub('[\(|\)|\<|/]', '-', sub)
					sub = sub.replace('\n', '').replace(' ', '-')
				elif re.match('\[', line):
					subsub = line.replace('\n', '').replace(' ', '-')
				else:
					match_value = re.search('[0-9]+', line)
					if match_value:
						value = match_value.group()
					else:
						value = 0
					category = re.sub(' +[0-9]+ ', '', line)
					category = re.sub('[\(|\)|\<|/]', '-', category)
					category = re.sub('\!', 'no-', category)
					category = category.replace('\n', '').replace(' ', '-')
					if sub in data:
						data[sub][category] = int(value)
					else:
						d = {}
						d[category] = int(value)
						data[sub] = d
			return data

	except Exception as e:
		logger.error('get data from stat file error:'+str(e))
	return None


def get_answer(begin_data,end_data):

	begin_answer = 0
	begin_error = 0
	for k in begin_data:
		if k == 'SERVFAIL':
			begin_error = begin_data[k]
		begin_answer = begin_answer + begin_data[k]

	end_answer = 0
	end_error = 0
	for k in end_data:
		if k == 'SERVFAIL':
			end_error = end_data[k]
		end_answer = end_answer + end_data[k]
	
	return end_answer - begin_answer,end_error - begin_error



def upload_to_ftp(dir_name,file_name,data_type):
	global ftp_ip, ftp_port, ftp_user, ftp_pwd, ftp_dir, logger
	
	dir_list = []
	if ftp_dir.find('/') >= 0:
		dir_list = ftp_dir.split('/')
		del(dir_list[0])
	else:
		dir_list = [ftp_dir]
	try:
		transport = paramiko.Transport((ftp_ip, ftp_port))
		transport.connect(username = ftp_user, password = ftp_pwd)
		sftp = paramiko.SFTPClient.from_transport(transport)
		listdir = sftp.listdir('/')
		for i in dir_list:
			if i not in listdir:
				sftp.mkdir(i)
				logger.warning('ftp upload dir not exit and create -> '+i)
			sftp.chdir(i)
			listdir = sftp.listdir('.')
		#if ftp_dir not in listdir:
			#sftp.mkdir(ftp_dir)
			#logger.error('ftp upload dir not exit and create-'+i)
		#sftp.chdir(ftp_dir)
		#listdir = sftp.listdir('.')
		if data_type not in listdir:
			sftp.mkdir(data_type)
			logger.warning('ftp upload dir not exit and create -> '+data_type)
		sftp.chdir(data_type)
		listdir = sftp.listdir('.')
		data_dir = time.strftime('%Y-%m-%d')
		if data_dir not in listdir:
			sftp.mkdir(data_dir)
			logger.warning('ftp upload dir not exit and create -> '+data_dir)
		sftp.chdir(data_dir)
		sftp.put(dir_name+file_name,file_name)
		sftp.close()
		transport.close()
	
	except Exception as e:
		logger.error('upload to sftp error:'+str(e))
		return False

	logger.info('upload file %s success' % file_name)
	return True


def get_top10_and_delay():
	global dnstap_file, logger
	target_file = '/tmp/zone.txt'
	try:
		with open(target_file,'w') as f:
			subprocess.check_call(['dnstap-read',dnstap_file],stdout=f, cwd = '.')
	except Exception as e:
		logger.error('dnstap-read error:'+str(e))
		return [],0 

	top,request,respond = {},{},{}

	try:
		with open(target_file,'r') as f:
			for s in f:
				l = s.split(' ')
				if l[5].split(':')[-1] == '53':
					if '->' in l:
						k = l[3]+l[5]+l[-1]
						request[k] = int(1000*float(l[1].split(':')[-1]))
					elif '<-' in l:
						k = l[3]+l[5]+l[-1]
						respond[k] = int(1000*float(l[1].split(':')[-1]))
						dname = l[-1].split('/')[0].split('.')
						if len(dname) > 1 and dname[-1].islower():
							domain = dname[-1]
							if domain in top:
								top[domain] += 1
							else:
								top[domain] = 1
	
		vals = list(top.values())
		vals.sort(reverse = True)

		if len(vals) > 10:
			vals = vals[:10]
	
		new_vals = []
		for i in vals:
			if i not in new_vals:
				new_vals.append(i)
	
		top10 = []
		for val in new_vals:
			k = [k for k, v in top.items() if v == val]
			for s in k:
				top10.append(s)

		total,count,avg_delay = 0,0,0
		for k in respond:
			if k in request:
				delay = respond[k] - request[k]
				if delay < 0:
					delay = 60000 - request[k] + respond[k]
				count += 1
				total += delay
		if count != 0:
			avg_delay = total//count
		return top10,avg_delay

	except Exception as e:
		logger.error('get top10 and delay error'+str(e))

	return [],0 


def upload_root_data(querys,respond,noerror):
	global operator, vendor, node_id, server_id, upload_delay, upload_format, fname_format, dns_id, zone_room_id
	top,delay = get_top10_and_delay()

	root_resove_data = {}
	file_name = ''
	root_resove_str_data = ''

	if fname_format == 'basic': 
		root_resove_data = {
			'dnsId': dns_id,
			'zoneRoomId' : zone_room_id,
			'serverId' : server_id,
			'beginTime': (datetime.datetime.now() - datetime.timedelta(minutes=5)).strftime('%Y-%m-%d %H:%M:%S'), 
			'endTime': time.strftime('%Y-%m-%d %H:%M:%S'),
			'timeStamp' : time.strftime('%Y-%m-%d %H:%M:%S'),
			'queryDelay': delay,
			'qps': querys//upload_delay,
			'queryCount': respond,
			'responseRate': 0 if querys == 0 else respond*100//querys,
			'resolveRate': 0 if querys == 0 else noerror*100//querys,
			'top10': top
		}
		root_resove_str_data = dns_id + '|' + zone_room_id + '|' + server_id + '|' + root_resove_data['beginTime']\
		+ '|' + root_resove_data['endTime'] + '|' + root_resove_data['timeStamp'] + '|' + str(delay)\
		+ '|' + str(root_resove_data['qps']) + '|' + str(respond) + '|' + str(root_resove_data['responseRate'])\
		+ '|' + str(root_resove_data['resolveRate']) + '|'
		if len(top) > 0:
			top_str = ''
			for i in top:
				top_str += i + ','
			root_resove_str_data += top_str[:-1]
		file_name = 'zoneQueryInfo_full_' + dns_id + '_0_' + time.strftime('%Y%m%d%H%M%S') + '.gz'
	elif fname_format == 'demo':
		root_resove_data = {
			'operator': operator,
			'vendor' : vendor,
			"timestamp" : time.strftime('%Y-%m-%d %H:%M:%S'),
			"data" : [{
				'id': node_id,
				'server-id': server_id,
				'begin-date': (datetime.datetime.now() - datetime.timedelta(minutes=5)).strftime('%Y-%m-%d %H:%M:%S'), 
				'end-date': time.strftime('%Y-%m-%d %H:%M:%S'),
				'qps': querys//upload_delay,
				'update-date': time.strftime('%Y-%m-%d %H:%M:%S'),
				'delay': delay,
				'resolution-count': respond,
				'response-success-rate': 0 if querys == 0 else respond*100//querys,
				'resolution-success-rate': 0 if querys == 0 else noerror*100//querys,
				'top10': top
			}
			]
		}
		file_name = 'zoneQuery' + '_' + operator + '_' + vendor + '_' + time.strftime('%Y%m%d%H%M%S') + '.gz'

	logger.info(root_resove_data)
	
	if upload_format == 'txt':
		logger.info(root_resove_str_data)
		try:
			with gzip.open('/var/drmsd_data/' + file_name, "wb") as f:
				f.write(bytes(root_resove_str_data, 'utf-8'))
			upload_to_ftp('/var/drmsd_data/',file_name,'16')
		except Exception as e:
			logger.error('upload root resove data error:'+str(e))
	elif upload_format == 'json':
		try:
			with gzip.open('/tmp/' + file_name, "wb") as f:
				data = json.dumps(root_resove_data,ensure_ascii=False,indent=4)
				f.write(bytes(data, 'utf-8'))
			upload_to_ftp('/tmp/',file_name,'16')
			os.remove('/tmp/' + file_name)
		except Exception as e:
			logger.error('upload root resove data error:'+str(e))
	elif upload_format == 'xml':
		try:
			with gzip.open('/tmp/' + file_name, "wb") as f:
				d = {'zoneQueryInfo' : root_resove_data}
				data = xml.dom.minidom.parseString(xmltodict.unparse(d)).toprettyxml(indent="\t")
				f.write(bytes(data, 'utf-8'))
			upload_to_ftp('/tmp/',file_name,'16')
			os.remove('/tmp/' + file_name)
		except Exception as e:
			logger.error('upload root resove data error:'+str(e))



def get_root_copy_list():
	global local, home, logger
	root_local_file = home + '/' + local
	try:
		with open(root_local_file, 'r') as f:
			data = f.read()
			named_data = MakeNamedDict(data)
			servers = named_data['orphan_zones']['.']['options']['server-addresses']
			root_copy_list = []
			for k in servers:
				root_copy_list.append(k)
			return root_copy_list
				
	except Exception as e:
		logger.error('get root copy list error:'+str(e))
	return []


def get_recursion_root_stat():
	global dnstap_file, logger
	target_file = '/tmp/zone.txt'
	root_copy_list = get_root_copy_list()
	root_ip_list = root_all_ip_list + root_copy_list 

	root_list = root_all_list
	root_list['root_copy'] = root_copy_list

	root_stat = {'a':0, 'b':0, 'c':0, 'd':0, 'e':0, 'f':0, 'g':0, 'h':0, 'i':0, 'j':0, 'k':0, 'l':0, 'm':0, 'root_copy':0}
	delay_stat = root_stat.copy()

	try:
		with open(target_file,'w') as f:
			subprocess.check_call(['dnstap-read',dnstap_file],stdout=f, cwd = '.')
	except Exception as e:
		logger.error('get recursion stat dnstap-read error:'+str(e))
		del root_stat['root_copy']
		del delay_stat['root_copy']
		return root_stat,0,0,delay_stat,0 

	root,request,respond = {},{},{}

	try:
		with open(target_file,'r') as f:
			for s in f:
				l = s.split(' ')
				if l[5].split(':')[-1] == '53':
				#after add root 13 delay stat
					if '->' in l:
						k = l[3]+l[5]+l[-1]
						request[k] = int(1000*float(l[1].split(':')[-1]))
					elif '<-' in l:
						k = l[3]+l[5]+l[-1]
						respond[k] = int(1000*float(l[1].split(':')[-1]))
						domain = l[5].split(':53')[0]
						if domain in root_ip_list:
							if domain in root:
								root[domain] += 1
							else:
								root[domain] = 1

		for k in root_list:
			for ip in root_list[k]:
				if ip in root:
					root_stat[k] += root[ip]
				
		total,count,avg_delay = 0,0,0
		for k in respond:
			if k in request:
				delay = respond[k] - request[k]
				if delay < 0:
					delay = 60000 - request[k] + respond[k]
				count += 1
				total += delay

		if count != 0:
			avg_delay = total//count

		dns_query = dns.message.make_query('.', 'NS')
		for k in root_list:
			if root_stat[k] > 0 and len(root_list[k]) > 0: 
				try:
					begin = datetime.datetime.now()
					response = dns.query.udp(dns_query, root_list[k][0], port = 53,timeout = 2)
					end = datetime.datetime.now()
					delay_stat[k] = (end - begin).microseconds//1000
				except Exception as e:
					logger.warning(k+' get root delay error:'+str(e))

		root_copy_cnt = root_stat['root_copy']
		root_copy_delay = delay_stat['root_copy']
		del root_stat['root_copy']
		del delay_stat['root_copy']
		return root_stat,avg_delay,root_copy_cnt,delay_stat,root_copy_delay

	except Exception as e:
		logger.warning('get recursion root 13 stat error:'+str(e))

	del root_stat['root_copy']
	del delay_stat['root_copy']
	return root_stat,0,0,delay_stat,0 


def upload_recursion_data(querys,respond,noerror,ipv4_request,ipv6_request):
	global operator, vendor, node_id, server_id, upload_delay, upload_format, fname_format, dns_id, zone_room_id
	root_count_dict,delay,root_copy_count,root_delay_dict,root_copy_delay = get_recursion_root_stat()

	recursion_resove_data = {}
	file_name = ''
	recursion_resove_str_data = ''
	recursion_root_str_data = ''
	root_file_name = ''

	if fname_format == 'basic': 
		recursion_resove_data = {
			'dnsId': dns_id,
			'zoneRoomId' : zone_room_id,
			'serverId' : server_id,
			'beginTime': (datetime.datetime.now() - datetime.timedelta(minutes=5)).strftime('%Y-%m-%d %H:%M:%S'), 
			'endTime': time.strftime('%Y-%m-%d %H:%M:%S'),
			'timeStamp' : time.strftime('%Y-%m-%d %H:%M:%S'),
			'queryDelay': delay,
			'qps': querys//upload_delay,
			'queryIpv4': ipv4_request,
			'queryIpvv6': ipv6_request,
			'responseRate': 0 if querys == 0 else respond*100//querys,
			'resolveRate': 0 if querys == 0 else noerror*100//querys,
			'count7706': root_copy_count, 
			'delay7706': root_copy_delay,
			'rootCountA': root_count_dict['a'],
			'RootCountB': root_count_dict['b'],
			'RootCountC': root_count_dict['c'],
			'RootCountD': root_count_dict['d'],
			'RootCountE': root_count_dict['e'],
			'RootCountF': root_count_dict['f'],
			'RootCountG': root_count_dict['g'],
			'RootCountH': root_count_dict['h'],
			'RootCountI': root_count_dict['i'],
			'RootCountJ': root_count_dict['j'],
			'RootCountK': root_count_dict['k'],
			'RootCountL': root_count_dict['l'],
			'rootCountM': root_count_dict['m'],
			'rootDelayA': root_delay_dict['a'],
			'RootDelayB': root_delay_dict['b'],
			'RootDelayC': root_delay_dict['c'],
			'RootDelayD': root_delay_dict['d'],
			'RootDelayE': root_delay_dict['e'],
			'RootDelayF': root_delay_dict['f'],
			'RootDelayG': root_delay_dict['g'],
			'RootDelayH': root_delay_dict['h'],
			'RootDelayI': root_delay_dict['i'],
			'RootDelayJ': root_delay_dict['j'],
			'RootDelayK': root_delay_dict['k'],
			'RootDelayL': root_delay_dict['l'],
			'rootDelayM': root_delay_dict['m']
		}
		recursion_resove_str_data = dns_id + '|' + zone_room_id + '|' + server_id + '|' + recursion_resove_data['beginTime']\
		+ '|' + recursion_resove_data['endTime'] + '|' + recursion_resove_data['timeStamp'] + '|' + str(delay)\
		+ '|' + str(recursion_resove_data['qps']) + '|' + str(ipv4_request) + '|' + str(ipv6_request)\
		+ '|' + str(recursion_resove_data['responseRate']) + '|' + str(recursion_resove_data['resolveRate'])\
		+ '|' + str(root_copy_count) + '|' + str(root_copy_delay) + '|' + str(root_count_dict['a'])\
		+ '|' + str(root_count_dict['b']) + '|' + str(root_count_dict['c']) + '|' + str(root_count_dict['d'])\
		+ '|' + str(root_count_dict['e']) + '|' + str(root_count_dict['f']) + '|' + str(root_count_dict['g'])\
		+ '|' + str(root_count_dict['h']) + '|' + str(root_count_dict['i']) + '|' + str(root_count_dict['j'])\
		+ '|' + str(root_count_dict['k']) + '|' + str(root_count_dict['l']) + '|' + str(root_count_dict['m'])\
		+ '|' + str(root_delay_dict['a']) + '|' + str(root_delay_dict['b']) + '|' + str(root_delay_dict['c'])\
		+ '|' + str(root_delay_dict['d']) + '|' + str(root_delay_dict['e']) + '|' + str(root_delay_dict['f'])\
		+ '|' + str(root_delay_dict['g']) + '|' + str(root_delay_dict['h']) + '|' + str(root_delay_dict['i'])\
		+ '|' + str(root_delay_dict['j']) + '|' + str(root_delay_dict['k']) + '|' + str(root_delay_dict['l'])\
		+ '|' + str(root_delay_dict['m'])
		file_name = 'dnsQueryInfo_full_' + dns_id + '_0_' + time.strftime('%Y%m%d%H%M%S') + '.gz'

		recursion_root_str_data = str(root_count_dict['a'])\
		+ '|' + str(root_count_dict['b']) + '|' + str(root_count_dict['c']) + '|' + str(root_count_dict['d'])\
		+ '|' + str(root_count_dict['e']) + '|' + str(root_count_dict['f']) + '|' + str(root_count_dict['g'])\
		+ '|' + str(root_count_dict['h']) + '|' + str(root_count_dict['i']) + '|' + str(root_count_dict['j'])\
		+ '|' + str(root_count_dict['k']) + '|' + str(root_count_dict['l']) + '|' + str(root_count_dict['m'])\
		+ '|' + dns_id + '|' + recursion_resove_data['timeStamp'] + '|' + str(querys) 
		root_file_name = 'rootQuery_full_' + dns_id + '_0_' + time.strftime('%Y%m%d%H%M%S') + '.gz'
	elif fname_format == 'demo':
		recursion_resove_data = {
			'operator': operator,
			'vendor' : vendor,
			'timestamp' : time.strftime('%Y-%m-%d %H:%M:%S'),
			'data' : [{
				'id': node_id,
				'server-id': server_id,
				'begin-date': (datetime.datetime.now() - datetime.timedelta(minutes=5)).strftime('%Y-%m-%d %H:%M:%S'), 
				'end-date': time.strftime('%Y-%m-%d %H:%M:%S'),
				'delay': delay,
				'qps': querys//upload_delay,
				'update-date': time.strftime('%Y-%m-%d %H:%M:%S'),
				'resolution-count-v4': ipv4_request,
				'resolution-count-v6': ipv6_request,
				'response-success-rate': 0 if querys == 0 else respond*100//querys,
				'resolution-success-rate': 0 if querys == 0 else noerror*100//querys,
				'query-7706-count': root_copy_count, 
				'query-7706-delay': root_copy_delay,
				'query-root-count': root_count_dict,
				'query-root-delay': root_delay_dict,
			}
			]
		}
		file_name = 'dnsQuery' + '_' + operator + '_' + vendor + '_' + time.strftime('%Y%m%d%H%M%S') + '.gz'

	logger.info(recursion_resove_data)

	if upload_format == 'txt':
		logger.info(recursion_resove_str_data)
		try:
			with gzip.open('/var/drmsd_data/' + file_name, "wb") as f:
				f.write(bytes(recursion_resove_str_data, 'utf-8'))
			upload_to_ftp('/var/drmsd_data/',file_name,'14')
			#with gzip.open('/var/drmsd_data/' + root_file_name, "wb") as f:
				#f.write(bytes(recursion_root_str_data, 'utf-8'))
			#upload_to_ftp('/var/drmsd_data/',root_file_name,'12')
		except Exception as e:
			logger.error('upload recursion data error:'+str(e))
	elif upload_format == 'json':
		try:
			with gzip.open('/tmp/' + file_name, "wb") as f:
				data = json.dumps(recursion_resove_data,ensure_ascii=False,indent=4)
				f.write(bytes(data, 'utf-8'))
			upload_to_ftp('/tmp/',file_name,'14')
			os.remove('/tmp/' + file_name)
		except Exception as e:
			logger.error('upload recursion data error:'+str(e))
	elif upload_format == 'xml':
		try:
			with gzip.open('/tmp/' + file_name, "wb") as f:
				d = {'dnsQueryInfo' : recursion_resove_data}
				data = xml.dom.minidom.parseString(xmltodict.unparse(d)).toprettyxml(indent="\t")
				f.write(bytes(data, 'utf-8'))
			upload_to_ftp('/tmp/',file_name,'14')
			os.remove('/tmp/' + file_name)
		except Exception as e:
			logger.error('upload recursion data error:'+str(e))



def upload_recursion_root_data():
	global upload_format, fname_format, dns_id, logger, stat_file

	begin_data = get_stat_data('/var/named/data/root_visit.txt')
	try:
		subprocess.call(['rndc','stats'])
		shutil.copy(stat_file,'/var/named/data/root_visit.txt')
	except Exception as e:
		logger.error('rndc stats error:'+str(e))
	end_data = get_stat_data('/var/named/data/root_visit.txt')

	querys = 0
	if begin_data != None and end_data != None:
		if 'Incoming-Requests' in begin_data and 'Incoming-Requests' in end_data:
			if 'QUERY' in begin_data['Incoming-Requests'] and 'QUERY' in end_data['Incoming-Requests']:
				querys = end_data['Incoming-Requests']['QUERY'] - begin_data['Incoming-Requests']['QUERY']

	root_count_dict,delay,root_copy_count,root_delay_dict,root_copy_delay = get_recursion_root_stat()

	recursion_root_str_data = str(root_count_dict['a'])\
	+ '|' + str(root_count_dict['b']) + '|' + str(root_count_dict['c']) + '|' + str(root_count_dict['d'])\
	+ '|' + str(root_count_dict['e']) + '|' + str(root_count_dict['f']) + '|' + str(root_count_dict['g'])\
	+ '|' + str(root_count_dict['h']) + '|' + str(root_count_dict['i']) + '|' + str(root_count_dict['j'])\
	+ '|' + str(root_count_dict['k']) + '|' + str(root_count_dict['l']) + '|' + str(root_count_dict['m'])\
	+ '|' + dns_id + '|' + time.strftime('%Y-%m-%d %H:%M:%S') + '|' + str(querys) 
	root_file_name = 'rootQuery_full_' + dns_id + '_0_' + time.strftime('%Y%m%d%H%M%S') + '.gz'

	logger.info(recursion_root_str_data)
	try:
		with gzip.open('/var/drmsd_data/' + root_file_name, "wb") as f:
			f.write(bytes(recursion_root_str_data, 'utf-8'))
		upload_to_ftp('/var/drmsd_data/',root_file_name,'12')
	except Exception as e:
		logger.error('upload recursion 15 minite root data error:'+str(e))


# test after must mod
def upload_recursion_root_one_day_data():
	global upload_format, fname_format, dns_id, logger, stat_file

	begin_data = get_stat_data('/var/named/data/root_visit.txt')
	try:
		subprocess.call(['rndc','stats'])
		shutil.copy(stat_file,'/var/named/data/root_visit.txt')
	except Exception as e:
		logger.error('rndc stats error:'+str(e))
	end_data = get_stat_data('/var/named/data/root_visit.txt')

	querys = 0
	if begin_data != None and end_data != None:
		if 'Incoming-Requests' in begin_data and 'Incoming-Requests' in end_data:
			if 'QUERY' in begin_data['Incoming-Requests'] and 'QUERY' in end_data['Incoming-Requests']:
				querys = end_data['Incoming-Requests']['QUERY'] - begin_data['Incoming-Requests']['QUERY']

	root_count_dict,delay,root_copy_count,root_delay_dict,root_copy_delay = get_recursion_root_stat()

	recursion_root_str_data = str(144*root_count_dict['a'])\
	+ '|' + str(144*root_count_dict['b']) + '|' + str(144*root_count_dict['c']) + '|' + str(144*root_count_dict['d'])\
	+ '|' + str(144*root_count_dict['e']) + '|' + str(144*root_count_dict['f']) + '|' + str(144*root_count_dict['g'])\
	+ '|' + str(144*root_count_dict['h']) + '|' + str(144*root_count_dict['i']) + '|' + str(144*root_count_dict['j'])\
	+ '|' + str(144*root_count_dict['k']) + '|' + str(144*root_count_dict['l']) + '|' + str(144*root_count_dict['m'])\
	+ '|' + dns_id + '|' + time.strftime('%Y-%m-%d %H:%M:%S') + '|' + str(querys) 
	root_file_name = 'rootQuery_full_' + dns_id + '_0_' + time.strftime('%Y%m%d%H%M%S') + '.gz'

	logger.info(recursion_root_str_data)
	try:
		with gzip.open('/var/drmsd_data/' + root_file_name, "wb") as f:
			f.write(bytes(recursion_root_str_data, 'utf-8'))
		upload_to_ftp('/var/drmsd_data/',root_file_name,'12')
	except Exception as e:
		logger.error('upload recursion root one day data error:'+str(e))


def get_transfer_ip_and_delay(soa):
	global run_file,logger

	target = 'serial ' + str(soa)
	try:
		with open(run_file) as f:
			l = f.readlines()
			for i in range(len(l)):
				if l[i].find(target) > 0:
					for v in l[i:]:
						if v.find('Transfer completed') > 0:
							res = v
							return int(1000*float(res.split(', ')[-1].split(' ')[0])) , res.split('#')[0].split(' ')[-1]

	except Exception as e:
		logger.warning('get transfer ip and delay error:'+str(e))
	return 0,'0.0.0.0'
		

def get_server_from_file():
	global root_source, home, logger
	standard_source_file = home + '/' + standard_source
	exigency_source_file = home + '/' + exigency_source
	try:
		server = ''
		with open(standard_source_file, 'r') as f:
			data = f.read()
			named_data = MakeNamedDict(data)
			servers = named_data['orphan_zones']['.']['options']['masters']
			for ip in servers:
				server += ip + ','
		with open(exigency_source_file, 'r') as f:
			data = f.read()
			named_data = MakeNamedDict(data)
			servers = named_data['orphan_zones']['.']['options']['masters']
			for ip in servers:
				server += ip + ','
		return server[:-1]

	except Exception as e:
		logger.warning('get server from root source file error:'+str(e))

	return ''


def get_transfer_ip_and_delay_from_file(soa):
	global root_source, home, logger
	root_source_file = home + '/' + root_source
	try:
		with open(root_source_file, 'r') as f:
			data = f.read()
			named_data = MakeNamedDict(data)
			servers = named_data['orphan_zones']['.']['options']['masters']
			dns_query = dns.message.make_query('.', 'SOA')
			for ip in servers:
				begin = datetime.datetime.now()
				res = dns.query.udp(dns_query, ip, port = 53,timeout = 2)
				end = datetime.datetime.now()
				for i in res.answer:
					for j in i.items:
						if j.serial == soa:
							return (end - begin).microseconds//1000,ip
	except Exception as e:
		logger.warning('get transfer ip and delay from swotch_root.zone error:'+str(e))
	return 0,'0.0.0.0'


def get_root_file_size():
	global root_source, home, logger
	root_source_file = home + '/' + root_source
	try:
		with open(root_source_file, 'r') as f:
			data = f.read()
			named_data = MakeNamedDict(data)
			return os.path.getsize('/var/named/'+named_data['orphan_zones']['.']['file'])
	except Exception as e:
		logger.warning('get root_copy file size error:'+str(e))
	return 0


def upload_root_run_data(soa):
	global operator, vendor, node_id, server_id, upload_delay, upload_format, fname_format, dns_id, zone_room_id
	
	result = 'get source or size error'
	delay,ip = get_transfer_ip_and_delay(soa)
	if delay == 0 and ip == '0.0.0.0': 
		delay,ip = get_transfer_ip_and_delay_from_file(soa)
	size = get_root_file_size()
	if delay != 0 and ip != '0.0.0.0' and size != 0:
		result = 'success'
	
	server = get_server_from_file()

	root_soa_data = {}
	file_name = ''
	root_soa_str_data = ''

	if fname_format == 'basic': 
		root_soa_data = {
			'dnsId': dns_id,
			'zoneRoomId' : zone_room_id,
			'serverId' : server_id,
			'serverIp' : server,
			'sourceIp' : ip,
			'timestamp' : time.strftime('%Y-%m-%d %H:%M:%S'),
			'zoneResult' : result,
			'zoneSize' : size,
			'soa' : soa,
			'zoneDelay' : delay
		}
		root_soa_str_data = dns_id + '|' + zone_room_id + '|' + server_id + '|' + server + '|' + ip\
		+ '|' + root_soa_data['timestamp'] + '|' + result + '|' + str(size) + '|' + str(soa) + '|' + str(delay)
		file_name = 'zoneOperation_full_' + dns_id + '_0_' + time.strftime('%Y%m%d%H%M%S') + '.gz'
	elif fname_format == 'demo':
		root_soa_data = {
			'operator': operator,
			'vendor' : vendor,
			'timestamp' : time.strftime('%Y-%m-%d %H:%M:%S'),
			'data' : {
				'id': node_id,
				'server-id': server_id,
				'ip': server,
				'source': ip,
				'update-date': time.strftime('%Y-%m-%d %H:%M:%S'),
				'result': result,
				'size': size,
				'soa': soa,
				'delay': delay
			}
		}
		file_name = 'zoneOperation' + '_' + operator + '_' + vendor + '_' + time.strftime('%Y%m%d%H%M%S') + '.gz'

	logger.info(root_soa_data)

	if upload_format == 'txt':
		logger.info(root_soa_str_data)
		try:
			with gzip.open('/var/drmsd_data/' + file_name, "wb") as f:
				f.write(bytes(root_soa_str_data, 'utf-8'))
			upload_to_ftp('/var/drmsd_data/',file_name,'15')
		except Exception as e:
			logger.error('upload root resove data error:'+str(e))
	elif upload_format == 'json':
		try:
			with gzip.open('/tmp/' + file_name, "wb") as f:
				data = json.dumps(root_soa_data,ensure_ascii=False,indent=4)
				f.write(bytes(data, 'utf-8'))
			upload_to_ftp('/tmp/',file_name,'15')
			os.remove('/tmp/' + file_name)
		except Exception as e:
			logger.error('upload root_copy run data error:'+str(e))
	elif upload_format == 'xml':
		try:
			with gzip.open('/tmp/' + file_name, "wb") as f:
				d = {'zoneOperation' : root_soa_data}
				data = xml.dom.minidom.parseString(xmltodict.unparse(d)).toprettyxml(indent="\t")
				f.write(bytes(data, 'utf-8'))
			upload_to_ftp('/tmp/',file_name,'15')
			os.remove('/tmp/' + file_name)
		except Exception as e:
			logger.error('upload root_copy run data error:'+str(e))



def upload_data(srv_type):
	global logger,tmp_stat_file

	begin_data = get_stat_data(tmp_stat_file)
	if begin_data == None:
		logger.warning('[%d] gennerate root begin stat error!' % os.getpid())
		return
	
	if get_stat_file() == False:
		logger.warning('[%d] gennerate stat file error!' % os.getpid())
		return

	end_data = get_stat_data(tmp_stat_file)
	if end_data == None:
		logger.warning('[%d] gennerate root end stat error!' % os.getpid())
		return
	
	querys = 0
	if 'Incoming-Requests' in begin_data and 'Incoming-Requests' in end_data:
		if 'QUERY' in begin_data['Incoming-Requests'] and 'QUERY' in end_data['Incoming-Requests']:
			querys = end_data['Incoming-Requests']['QUERY'] - begin_data['Incoming-Requests']['QUERY']

	respond,serverfail = 0,0
	if 'Outgoing-Rcodes' in begin_data and 'Outgoing-Rcodes' in end_data:
		respond,serverfail = get_answer(begin_data['Outgoing-Rcodes'],end_data['Outgoing-Rcodes'])
	
	if srv_type == 'root_copy':
		upload_root_data(querys,respond,respond-serverfail)
	elif srv_type == 'recursion':
		ipv4_req,ipv6_req = 0,0
		if 'Name-Server-Statistics' in begin_data and 'Name-Server-Statistics' in end_data:
			if 'IPv4-requests-received' in begin_data['Name-Server-Statistics'] and 'IPv4-requests-received' in end_data['Name-Server-Statistics']:
				ipv4_req = end_data['Name-Server-Statistics']['IPv4-requests-received'] - begin_data['Name-Server-Statistics']['IPv4-requests-received']
			if 'IPv6-requests-received' in begin_data['Name-Server-Statistics'] and 'IPv6-requests-received' in end_data['Name-Server-Statistics']:
				ipv6_req = end_data['Name-Server-Statistics']['IPv6-requests-received'] - begin_data['Name-Server-Statistics']['IPv6-requests-received']

		upload_recursion_data(querys,respond,respond-serverfail,ipv4_req,ipv6_req)
	

def get_root_copy_soa():
	global logger
	try:
		dns_query = dns.message.make_query('.', 'SOA')
		res = dns.query.udp(dns_query, '127.0.0.1', port = 53,timeout = 2)
		for i in res.answer:
			for j in i.items:
				return j.serial
	except Exception as e:
		logger.warning('get root copy soa error:'+str(e))
	return 0


def xgj_upload_task():
	global server_type, upload_delay, logger, upload_format, fname_format

	if server_type != 'recursion' and server_type != 'root_copy':
		logger.warning('server_type conf error and let server_type = recursion')
		server_type = 'recursion'

	if get_stat_file() == False:
		logger.error('[%d] get stat file error!' % os.getpid())
	
	root_soa,loop_count,recursion_root_count,root_run_count = 0,0,0,0
	while True:
		if int(share_delay.value) == 900 and root_run_count * 60 >= 900:
			root_run_count = 0
			if server_type == 'root_copy':
				now_soa = get_root_copy_soa()
				if now_soa > 0:
					upload_root_run_data(now_soa)
			elif server_type == 'recursion':
				upload_recursion_root_data()
		elif int(share_delay.value) == 86400 and recursion_root_count * 60 >= 86400:
			recursion_root_count = 0
			upload_recursion_root_one_day_data()

		if server_type == 'root_copy':
			now_soa = get_root_copy_soa()
			if now_soa > 0:
				if root_soa != now_soa:
					root_soa = now_soa
					upload_root_run_data(now_soa)

		time.sleep(60)
		loop_count += 1
		recursion_root_count += 1
		root_run_count += 1
		if loop_count * 60 >= 600 and upload_format == 'txt' and fname_format == 'basic':
			loop_count = 0
			upload_data(server_type)
		elif upload_format == 'json' and fname_format == 'demo' and loop_count * 60 >= int(share_delay.value):
			loop_count = 0
			upload_data(server_type)


def get_delay(data):
	request,respond = {},{}
	try:
		for s in data:
			l = s.split(' ')
			if '->' in l:
				k = l[3]+l[5]+l[-1]
				request[k] = int(1000*float(l[1].split(':')[-1]))
			elif '<-' in l:
				k = l[3]+l[5]+l[-1]
				respond[k] = int(1000*float(l[1].split(':')[-1]))
	
		total,count,avg_delay = 0,0,0
		for k in respond:
			if k in request:
				delay = respond[k] - request[k]
				if delay < 0:
					delay = 60000 - request[k] + respond[k]
				count += 1
				total += delay
		if count != 0:
			avg_delay = total//count
		return avg_delay
	except Exception as e:
		logger.error('get recursion iter delay error'+str(e))
	return 0


def get_recursion_iter_data():
	dnstap_file = waj_conf['named']['dnstap_file']
	target_file = '/tmp/root_zone.txt'

	root_copy_list = get_root_copy_list()
	root_ip_list = root_all_ip_list + root_copy_list 

	root_list = root_all_list
	root_list['root_copy'] = root_copy_list

	try:
		with open(target_file,'w') as f:
			subprocess.check_call(['dnstap-read',dnstap_file],stdout=f, cwd = '.')
	except Exception as e:
		logger.error('get recursion stat dnstap-read error:'+str(e))
		return '' 

	request_tld = {'com':0, 'net':0, 'org':0, 'cn':0}
	response_tld = request_tld.copy()
	root_request_stat = {'a':0, 'b':0, 'c':0, 'd':0, 'e':0, 'f':0, 'g':0, 'h':0, 'i':0, 'j':0, 'k':0, 'l':0, 'm':0, 'root_copy':0}
	delay_stat = root_request_stat.copy()
	root_response_stat = root_request_stat.copy()

	root_request,root_response,tld_data = {},{},{}
	#a,b,c,d,e,f,g,h,i,j,k,l,m,com,net,org,cn = [],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[]

	try:
		with open(target_file,'r') as f:
			for s in f:
				l = s.split(' ')
				if l[5].split(':')[-1] == '53':
				#after add root 13 delay stat
					if '->' in l:
						domain = l[5].split(':53')[0]
						if domain in root_ip_list:
							if domain in root_request:
								root_request[domain] += 1
							else:
								root_request[domain] = 1
						dname = l[-1].split('/')[0].split('.')
						if len(dname) > 1 and dname[-1].islower():
							if dname[-1] in request_tld:
								request_tld[dname[-1]] += 1
								if dname[-1] in tld_data:
									tld_data[dname[-1]].append(s)
								else:
									tld_data[dname[-1]] = []
									tld_data[dname[-1]].append(s)
					elif '<-' in l:
						domain = l[5].split(':53')[0]
						if domain in root_ip_list:
							if domain in root_response:
								root_response[domain] += 1
							else:
								root_response[domain] = 1
						dname = l[-1].split('/')[0].split('.')
						if len(dname) > 1 and dname[-1].islower():
							if dname[-1] in response_tld:
								response_tld[dname[-1]] += 1
								if dname[-1] in tld_data:
									tld_data[dname[-1]].append(s)
								else:
									tld_data[dname[-1]] = []
									tld_data[dname[-1]].append(s)
									
		for k in root_list:
			for ip in root_list[k]:
				if ip in root_request:
					root_request_stat[k] += root_request[ip]
				if ip in root_response:
					root_response_stat[k] += root_response[ip]
				
		dns_query = dns.message.make_query('.', 'NS')
		for k in root_list:
			if root_response_stat[k] > 0 and len(root_list[k]) > 0: 
				try:
					begin = datetime.datetime.now()
					response = dns.query.udp(dns_query, root_list[k][0], port = 53,timeout = 2)
					end = datetime.datetime.now()
					delay_stat[k] = (end - begin).microseconds//1000
				except Exception as e:
					logger.warning(k+' get root delay error:'+str(e))
		
		iter_data = {
			'nodeId': '0'+waj_conf['upload']['org_id']+'02'+waj_conf['upload']['area_id']+'02',
			'rootList':[		
				{
					'ns':'a.root-servers.net',
					'queryCnt':str(root_request_stat['a']),
					'sucRespCnt':str(root_response_stat['a']),
					'resolveAvgT':str(delay_stat['a'])
				},
				{
					'ns':'b.root-servers.net',
					'queryCnt':str(root_request_stat['b']),
					'sucRespCnt':str(root_response_stat['b']),
					'resolveAvgT':str(delay_stat['d'])
				},
				{
					'ns':'c.root-servers.net',
					'queryCnt':str(root_request_stat['c']),
					'sucRespCnt':str(root_response_stat['c']),
					'resolveAvgT':str(delay_stat['c'])
				},
				{
					'ns':'d.root-servers.net',
					'queryCnt':str(root_request_stat['d']),
					'sucRespCnt':str(root_response_stat['d']),
					'resolveAvgT':str(delay_stat['d'])
				},
				{
					'ns':'e.root-servers.net',
					'queryCnt':str(root_request_stat['e']),
					'sucRespCnt':str(root_response_stat['e']),
					'resolveAvgT':str(delay_stat['e'])
				},
				{
					'ns':'f.root-servers.net',
					'queryCnt':str(root_request_stat['f']),
					'sucRespCnt':str(root_response_stat['f']),
					'resolveAvgT':str(delay_stat['f'])
				},
				{
					'ns':'g.root-servers.net',
					'queryCnt':str(root_request_stat['g']),
					'sucRespCnt':str(root_response_stat['g']),
					'resolveAvgT':str(delay_stat['g'])
				},
				{
					'ns':'h.root-servers.net',
					'queryCnt':str(root_request_stat['h']),
					'sucRespCnt':str(root_response_stat['h']),
					'resolveAvgT':str(delay_stat['h'])
				},
				{
					'ns':'i.root-servers.net',
					'queryCnt':str(root_request_stat['i']),
					'sucRespCnt':str(root_response_stat['i']),
					'resolveAvgT':str(delay_stat['i'])
				},
				{
					'ns':'j.root-servers.net',
					'queryCnt':str(root_request_stat['j']),
					'sucRespCnt':str(root_response_stat['j']),
					'resolveAvgT':str(delay_stat['j'])
				},
				{
					'ns':'k.root-servers.net',
					'queryCnt':str(root_request_stat['k']),
					'sucRespCnt':str(root_response_stat['k']),
					'resolveAvgT':str(delay_stat['k'])
				},
				{
					'ns':'l.root-servers.net',
					'queryCnt':str(root_request_stat['l']),
					'sucRespCnt':str(root_response_stat['l']),
					'resolveAvgT':str(delay_stat['l'])
				},
				{
					'ns':'m.root-servers.net',
					'queryCnt':str(root_request_stat['m']),
					'sucRespCnt':str(root_response_stat['m']),
					'resolveAvgT':str(delay_stat['m'])
				}
			],
			'rcopyRCnt':str(root_response_stat['root_copy']),
			'rcopyRAvgT':str(delay_stat['root_copy']),
			'tldList':[
				{
					'tldName':'com',
					'queryCnt':str(request_tld['com']),
					'sucRespCnt':str(response_tld['com']),
					'resolveAvgT':str(get_delay(tld_data['com'])) if 'com' in tld_data else '0'
				},
				{
					'tldName':'net',
					'queryCnt':str(request_tld['net']),
					'sucRespCnt':str(response_tld['net']),
					'resolveAvgT':str(get_delay(tld_data['net'])) if 'net' in tld_data else '0'
				},
				{
					'tldName':'org',
					'queryCnt':str(request_tld['org']),
					'sucRespCnt':str(response_tld['org']),
					'resolveAvgT':str(get_delay(tld_data['org'])) if 'org' in tld_data else '0'
				},
				{
					'tldName':'cn',
					'queryCnt':str(request_tld['cn']),
					'sucRespCnt':str(response_tld['cn']),
					'resolveAvgT':str(get_delay(tld_data['cn'])) if 'cn' in tld_data else '0'
				}
			],
			'statPeriod':str(waj_conf['upload']['delay']),
			'timeStamp':time.strftime('%Y-%m-%dT%H:%M:%SZ')
		}

		#print(json.dumps(iter_data,ensure_ascii=False,indent=4))
		logger.info(json.dumps(iter_data,ensure_ascii=False,indent=4))

		return json.dumps(iter_data)

	except Exception as e:
		logger.warning('get recursion root 13 stat error:'+str(e))

	return '' 


# '2' '54' json_str_data
def upload_waj_data(subsysid, intfid, json_data):
	
	while True:
		try:
			hashMode        = waj_conf['security']['hash_mode']
			encryptMode     = waj_conf['security']['encrypt_mode']
			compressMode    = waj_conf['security']['compress_mode']
			
			url                 = 'https://'+waj_conf['upload']['ip']+':'+waj_conf['upload']['port']+'/'+intfid+'/'+waj_conf['upload']['org_id']
			randVal             = bytes(''.join(random.sample(string.ascii_letters, 20)), 'utf-8')
			user_pwd            = bytes(waj_conf['security']['user_pwd'], 'utf-8')
			data_pwd            = bytes(waj_conf['security']['data_pwd'], 'utf-8')
			commandVersion      = 'v0.1'
			data                = bytes(json_data,'utf-8')
			
			if hashMode == '0':
				_hashed_pwd = user_pwd + randVal
			elif hashMode == '1':
				_hashed_pwd = hashlib.md5(user_pwd + randVal).hexdigest()
			elif hashMode == '2':
				_hashed_pwd = hashlib.sha1(user_pwd + randVal).hexdigest()
			elif hashMode == '3':
				_hashed_pwd = hashlib.sha256(user_pwd + randVal).hexdigest()
			elif hashMode == '11': pass
			else :
				_hashed_pwd = user_pwd + randVal

			pwdHash = base64.b64encode(_hashed_pwd.encode('utf-8'))
			
			if compressMode == '0': _compressed_data = data
			elif compressMode == '1': _compressed_data = zlib.compress(data)
			
			if encryptMode == '1':
				e = AESCipher(waj_conf['security']['aes_key'].encode('utf-8'), waj_conf['security']['aes_iv'].encode('utf-8'))
				_encrypted_data = e.encrypt(_compressed_data)
			elif encryptMode == '2'   : pass
			elif encryptMode == '11'   : pass
			elif encryptMode == '12'   : pass
			elif encryptMode == '13'   : pass
			elif encryptMode == '14'   : pass
			else: _encrypted_data = _compressed_data
			
			data = base64.b64encode(_encrypted_data)
			
			if hashMode == '0':
				_hashed_data = _compressed_data + data_pwd
			elif hashMode == '1':
				_hashed_data = hashlib.md5(_compressed_data + data_pwd).hexdigest()
			elif hashMode == '2':
				_hashed_data = hashlib.sha1(_compressed_data + data_pwd).hexdigest()
			elif hashMode == '3':
				_hashed_data = hashlib.sha256(_compressed_data + data_pwd).hexdigest()
			elif hashMode == '11': pass
			else :
				_hashed_pwd = data_pwd + randVal
			
			dataHash = base64.b64encode(_hashed_data.encode('utf-8'))
			
			requestData = {
				'uuid'          : str(uuid.uuid4()),
				'orgId'         : waj_conf['upload']['org_id'],
				'subsysId'      : subsysid,
				'intfId'        : intfid,
				'intfVer'       : commandVersion,
				'timeStamp'     : time.strftime('%Y-%m-%dT%H:%M:%SZ'),
				'randVal'       : randVal.decode(),
				'pwdHash'       : pwdHash.decode(),
				'encryptMode'   : encryptMode,
				'hashMode'      : hashMode,
				'compressMode'  : compressMode,
				'dataTag'       : '0',
				'data'          : data.decode(),
				'dataHash'      : dataHash.decode()
			}

			#print(json.dumps(requestData,ensure_ascii=False,indent=4))
			logger.info(json.dumps(requestData,ensure_ascii=False,indent=4))
            
			ret = requests.post(url, json.dumps(requestData), verify=False)
			retData = json.loads(ret.text)
			if retData.get('errorCode') == '0':
				logger.info('upload recursion iter data success!!')
				break
			else:
				logger.warning('upload recursion iter data failed : {}'.format(ret.text))
				sleep(5)
				continue

		except Exception as e:
			#print('catch a exception: {}'.format(e))
			logger.warning('catch a exception: {}'.format(e))
			sleep(5)
			continue



def waj_upload_task():
	while True:
		# int(share_delay.value) 根据周期统计
		sleep(waj_conf['upload']['delay'])
		upload_waj_data('2', '54', get_recursion_iter_data())


try:
	config = ConfigParser()
	config.read('/etc/drmsd.ini')
	listen_port = config.getint('network', 'port')
	ackhost = config.get('network', 'ackhost')
	ackport = config.getint('network', 'ackport')

	gPwd = config.get('security', 'secret')
	gAESKey = config.get('security', 'aes_key')
	gAESIV = config.get('security', 'aes_iv')

	home = config.get('named-conf', 'home')
	rndc = config.get('named-conf', 'rndc')
	switch = config.get('named-conf', 'switch')
	std = config.get('named-conf', 'std')
	local = config.get('named-conf', 'local')
	stat_file = config.get('named-conf', 'stat_file')
	tmp_stat_file = config.get('named-conf', 'tmp_stat_file')
	run_file = config.get('named-conf', 'run_file')
	dnstap_file = config.get('named-conf', 'dnstap_file')

	root_source = config.get('source', 'root_source')
	standard_source = config.get('source', 'standard_source')
	exigency_source = config.get('source', 'exigency_source')

	ftp_ip = config.get('ftp', 'ip')
	ftp_port = config.getint('ftp', 'port')
	ftp_user = config.get('ftp', 'user')
	ftp_pwd = config.get('ftp', 'pwd')
	ftp_dir = config.get('ftp', 'dir')

	operator = config.get('server', 'operator')
	vendor = config.get('server', 'vendor')
	server_type = config.get('server', 'server_type')
	node_id = config.get('server', 'node_id')
	server_id = config.get('server', 'server_id')
	upload_delay = config.getint('server', 'upload_delay')
	upload_format = config.get('server', 'upload_format')
	fname_format = config.get('server', 'fname_format')
	dns_id = config.get('server', 'dns_id')
	zone_room_id = config.get('server', 'zone_room_id')

	share_delay = multiprocessing.Value('d', upload_delay)

	#waj conf
	start_mode = config.get('start', 'mode')

	network = {}
	network['ip'] = config.get('local-net', 'ip')
	network['port'] = config.getint('local-net', 'port')
	waj_conf['local-net'] = network
	
	named = {}
	named['dnstap_file'] = config.get('named', 'dnstap_file')
	named['local_root'] = config.get('named', 'local_root')
	named['std_root'] = config.get('named', 'std_root')
	waj_conf['named'] = named
	
	upload = {}
	upload['ip'] = config.get('upload', 'ip')
	upload['port'] = config.get('upload', 'port')
	upload['delay'] = config.getint('upload', 'delay')
	upload['org_id'] = config.get('upload', 'org_id')
	upload['area_id'] = config.get('upload', 'area_id')
	waj_conf['upload'] = upload

	security = {}
	security['user_pwd'] = config.get('waj-security', 'user_pwd')
	security['data_pwd'] = config.get('waj-security', 'data_pwd')
	security['aes_key'] = config.get('waj-security', 'aes_key')
	security['aes_iv'] = config.get('waj-security', 'aes_iv')
	security['hash_mode'] = config.get('waj-security', 'hash_mode')
	security['encrypt_mode'] = config.get('waj-security', 'encrypt_mode')
	security['compress_mode'] = config.get('waj-security', 'compress_mode')
	waj_conf['security'] = security

except Exception as e:
	print('load conf or create log error:'+str(e))
	sys.exit(1)


if __name__ == '__main__':
#with daemon.DaemonContext():
	logger = logging.getLogger('drmsd')
	logger.setLevel(level = logging.INFO)
	handler = logging.FileHandler("/var/log/drmsd.log")
	handler.setLevel(logging.INFO)
	formatter = logging.Formatter('%(asctime)s|%(lineno)d|%(levelname)s|%(message)s')
	handler.setFormatter(formatter)
	logger.addHandler(handler)

	logger.info('main process start at: %s' % time.ctime())

	while True:
		if start_mode == 'xgj':
			p = multiprocessing.Process(target = xgj_main_task, args = ())
			p1 = multiprocessing.Process(target = xgj_upload_task, args = ())
			p.start()
			p1.start()
			p.join()
			p1.join()
		elif start_mode == 'waj':
			p2 = multiprocessing.Process(target = waj_upload_task, args = ())
			p2.start()
			p2.join()
		elif start_mode == 'all':
			p = multiprocessing.Process(target = xgj_main_task, args = ())
			p1 = multiprocessing.Process(target = xgj_upload_task, args = ())
			p2 = multiprocessing.Process(target = waj_upload_task, args = ())
			p.start()
			p1.start()
			p2.start()
			p.join()
			p1.join()
			p2.join()

	logger.info('main process end at: %s' % time.ctime())
 

