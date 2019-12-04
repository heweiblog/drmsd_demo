#!/usr/bin/python3
# -*- coding: utf-8 -*-

from __future__ import print_function

import os, pwd, sys, re, time, datetime, logging, random, string, logging.handlers, gzip, paramiko
import multiprocessing, subprocess, requests, urllib3, uuid
from threading import Timer
from configparser import ConfigParser
from Crypto.Cipher import AES

from iscpy.iscpy_dns.named_importer_lib import *
import base64, hashlib, zlib, json, lxml.etree, pexpect, dns, dns.resolver

from time import sleep
import threading, binascii, xml.dom.minidom, shutil, xmltodict, filecmp

from spyne import ServiceBase
from spyne.protocol.soap import Soap11
from spyne.decorator import rpc
from spyne.model.primitive import Integer, Int, Long, Unicode
from spyne.model.complex import Iterable
from spyne.application import Application
from spyne.util.wsgi_wrapper import WsgiMounter
from spyne.util.etreeconv import root_etree_to_dict
from wsgiref.simple_server import make_server

import osa, daemon

try:
	config = ConfigParser()
	config.read('/etc/drmsd.ini')
	listen_port = config.getint('network', 'port')
	ackhost = config.get('network', 'ackhost')
	ackport = config.getint('network', 'ackport')

	gPwd = config.get('security', 'secret')
	dataPwd = config.get('security', 'data_pwd')
	gAESKey = config.get('security', 'aes_key')
	gAESIV = config.get('security', 'aes_iv')

	switch = config.get('recursion', 'switch')
	std = config.get('recursion', 'std')
	local = config.get('recursion', 'local')

	stat_file = config.get('named-conf', 'stat_file')
	tmp_stat_file = config.get('named-conf', 'tmp_stat_file')
	run_file = config.get('named-conf', 'run_file')
	dnstap_file = config.get('named-conf', 'dnstap_file')
	src_dnstap_file = config.get('named-conf', 'src_dnstap_file')
	tmp_dnstap_file = config.get('named-conf', 'tmp_dnstap_file')
	conf_file = config.get('named-conf', 'conf_file')
	rndc = config.get('named-conf', 'rndc')

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
	dns_id = config.get('server', 'dns_id')
	zone_room_id = config.get('server', 'zone_room_id')

	share_delay = multiprocessing.Value('d', 86400)

except Exception as e:
	print('load conf or create log error:'+str(e))
	sys.exit(1)


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

	sleep(1) 
	result = bytes(gen_commandack_result(dnsId, commandSequence, commandType, 0 if resultCode==0 else 2), encoding = 'utf-8')
	randVal = bytes(''.join(random.sample(string.ascii_letters, 20)), 'utf-8')
	lPwd = bytes(gPwd,'utf-8')
	lData = bytes(dataPwd,'utf-8')

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
		_hashed_result = _compressed_result + lData
		resultHash = base64.b64encode(_hashed_result)
	elif hashAlgorithm == 1: 
		_hashed_result = hashlib.md5(_compressed_result + lData).digest()
		resultHash = base64.b64encode(binascii.b2a_hex(_hashed_result))
	elif hashAlgorithm == 2: 
		_hashed_result = hashlib.sha1(_compressed_result + lData).digest()
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
	raw = base64.b64decode(command.encode('utf-8'))
	if (gAESKey is not None) and (encryptAlgorithm == 1):
		data = aesDecode(raw)
	else: data = raw
	if hashAlgorithm == 0: hashed = data + dataPwd.encode('utf-8')
	elif hashAlgorithm == 1: hashed = hashlib.md5((data + dataPwd.encode('utf-8'))).digest()
	elif hashAlgorithm == 2: hashed = hashlib.sha1((data + dataPwd.encode('utf-8'))).digest()
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


def switch_named_file(target,source,clear):
	if os.path.exists(target) == False:
		logger.error('[%d] file[%s] not exist error!' % os.getpid(),target)
		return False
	
	if source == root_source:
		try:
			with open(target, 'r') as f:
				data = f.read()
				named_data = MakeNamedDict(data)
				slave_file = named_data['orphan_zones']['.']['file']
			if os.path.exists(slave_file):
				os.remove(slave_file)
		except Exception as e:
			logger.warning('del root copy slave file catch exption {}'.format(e))

	try:
		subprocess.check_call(['ln', '-f', '-s', target, source], cwd = '/etc')
	except subprocess.CalledProcessError:
		logger.error('[%d] create link path error!' % os.getpid())
		return False

	try:
		subprocess.check_call([rndc, 'reconfig'], cwd = '/etc')
	except subprocess.CalledProcessError:
		logger.error('rndc reconfig error!')
		return False
	
	try:
		if clear == '1':
			subprocess.check_call([rndc, 'flush'], cwd = '/etc')
			logger.info('swutch and clear all cache')
		#elif clear == '0':
			#subprocess.check_call([rndc, 'flushname', domain], cwd = '/etc')
			#logger.info('swutch and clear root cache')
	except subprocess.CalledProcessError:
		logger.error('rndc flush cache error!')
		return False

	logger.warn('[%d] root switch to `%s`' % (os.getpid(), target))
	return True


def upload_switch_result(target, dnsId, commandId):

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


def switch_rootca(stdon, delay, dnsId, commandType, commandId, hashAlgorithm, compressionFormat, encryptAlgorithm, clear):
	target = std if stdon else local
	if switch_named_file(target,switch,clear):
		upload_switch_result(target, dnsId, commandId)
		return genResult(0, commandType, commandId, dnsId, hashAlgorithm, compressionFormat, encryptAlgorithm)
	return genResult(900, commandType, commandId, dnsId, hashAlgorithm, compressionFormat, encryptAlgorithm)


def check_root_copy_data_source(is_exigency):
	d1,d2='',''
	with open(root_source,'r') as f:
		d1 = f.read()
	if is_exigency:
		with open(exigency_source,'r') as f:
			d2 = f.read()
	else:
		with open(standard_source,'r') as f:
			d2 = f.read()
	if d1 == d2:
		return True
	return False


def switch_root_source(is_exigency, delay, dnsId, commandType, commandId, hashAlgorithm, compressionFormat, encryptAlgorithm):
	target = exigency_source if is_exigency else standard_source
	if check_root_copy_data_source(is_exigency):
		logger.info('root copy data source already at {}'.format(target))
		upload_switch_result(target, dnsId, commandId)
		return genResult(0, commandType, commandId, dnsId, hashAlgorithm, compressionFormat, encryptAlgorithm)
	if switch_named_file(target,root_source,'0'):
		upload_switch_result(target, dnsId, commandId)
		return genResult(0, commandType, commandId, dnsId, hashAlgorithm, compressionFormat, encryptAlgorithm)
	return genResult(900, commandType, commandId, dnsId, hashAlgorithm, compressionFormat, encryptAlgorithm)


def switch_root_direction(cmd, commandType, dnsId, hashAlgorithm, compressionFormat, encryptAlgorithm):
	ele = lxml.etree.fromstring(cmd)
	_commandId = xmlget(ele, 'commandId')
	_type = xmlget(ele, 'type')
	_urgency = xmlget(ele, 'urgency')
	_datasources = xmlget(ele, 'datasources')
	_clearcache = xmlget(ele, 'clearCache')

	if _type != None:
		logger.info('switch root.ca type=%s' % _type)
		return switch_rootca(True if _type != '1' else False, 
			(2 * 60 * 60) if _urgency == '1' else (10 * 60), 
			dnsId, 8, _commandId, hashAlgorithm, 
			compressionFormat, encryptAlgorithm, _clearcache)

	if _datasources != None:
		logger.info('switch root source datasources=%s' % _datasources)
		return switch_root_source(True if _datasources != '1' else False, 
			(2 * 60 * 60) if _urgency == '1' else (10 * 60), 
			dnsId, 8, _commandId, hashAlgorithm, 
			compressionFormat, encryptAlgorithm)

	return genResult(900, commandType, _commandId, dnsId, hashAlgorithm, compressionFormat, encryptAlgorithm)


def switch_exigency_status(cmd, commandType, dnsId, hashAlgorithm, compressionFormat, encryptAlgorithm):
	ele = lxml.etree.fromstring(cmd)
	_commandId = xmlget(ele, 'commandId')
	_type = xmlget(ele, 'type')

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
		try:
			if not certificate(pwdHash, randVal, hashAlgorithm):
				logger.error('command certificate error')
				return genResult(2, commandType, None, dnsId, hashAlgorithm, compressionFormat, encryptAlgorithm) 
			cmd = deCMDPre(command, compressionFormat, commandHash,hashAlgorithm, encryptAlgorithm)
			if not cmd:
				logger.error('webService Malformed content do deCMDPre error')
				return genResult(5, commandType, None, dnsId, hashAlgorithm, compressionFormat, encryptAlgorithm)
			#command_func = {18:switch_root_direction,19:switch_exigency_status,15:handle_white_domain}
			command_func = {18:switch_root_direction,19:switch_exigency_status}
			if commandType in command_func:
				return command_func[commandType](cmd, commandType, dnsId, hashAlgorithm, compressionFormat, encryptAlgorithm)
		except Exception as e: 
			logger.error('command error:{}'.format(e))
			return genResult(900, commandType, None, dnsId, hashAlgorithm, compressionFormat, encryptAlgorithm)
        


def xgj_main_task():
	application = Application([DRMSService],'http://webservice.ack.dns.act.com/', 
			in_protocol = Soap11(validator = 'lxml'), 
			out_protocol = Soap11())

	wsgi_app = WsgiMounter({'DNSWebService' : application})
	server = make_server('0.0.0.0', listen_port, wsgi_app)
	server.serve_forever()


def get_stat_file():
	if os.path.exists(stat_file):
		os.remove(stat_file)
	if os.path.exists(tmp_stat_file):
		os.remove(tmp_stat_file)
	try:
		subprocess.call([rndc,'stats'])
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
	dir_list = []
	if ftp_dir.find('/') >= 0:
		dir_list = ftp_dir.split('/')
		del(dir_list[0])
	else:
		dir_list = [ftp_dir]
	try:
		transport = paramiko.Transport((ftp_ip, ftp_port))
		transport.connect(username = ftp_user, password = ftp_pwd)
		transport.banner_timeout = 30
		sftp = paramiko.SFTPClient.from_transport(transport)
		listdir = sftp.listdir('/')
		for i in dir_list:
			if i not in listdir:
				sftp.mkdir(i)
				logger.warning('ftp upload dir not exit and create -> '+i)
			sftp.chdir(i)
			listdir = sftp.listdir('.')
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


def xgj_cache_data_and_upload(file_name,data,upload_dir):
	logger.info(data)
	try:
		cache_dir = '/var/drmsd_data/'+time.strftime('%Y%m%d')+'/'
		if os.path.exists(cache_dir) == False:
			os.mkdir(cache_dir)
		with gzip.open(cache_dir + file_name, "wb") as f:
			f.write(bytes(data, 'utf-8'))
		upload_to_ftp(cache_dir,file_name,upload_dir)
	except Exception as e:
		logger.error('upload data error:'+str(e))


def get_root_copy_list():
	try:
		with open(local, 'r') as f:
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


def get_transfer_ip_and_delay(soa):
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
	try:
		server = ''
		with open(standard_source, 'r') as f:
			data = f.read()
			named_data = MakeNamedDict(data)
			servers = named_data['orphan_zones']['.']['options']['masters']
			for ip in servers:
				server += ip + ','
		with open(exigency_source, 'r') as f:
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
	try:
		with open(root_source, 'r') as f:
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
	try:
		with open(root_source, 'r') as f:
			data = f.read()
			named_data = MakeNamedDict(data)
			return os.path.getsize(named_data['orphan_zones']['.']['file'])
	except Exception as e:
		logger.warning('get root_copy file size error:'+str(e))
	return 0


def upload_root_run_data(soa):
	result = 'get source or size error'
	delay,ip = get_transfer_ip_and_delay(soa)
	if delay == 0 and ip == '0.0.0.0': 
		delay,ip = get_transfer_ip_and_delay_from_file(soa)
	size = get_root_file_size()
	if delay != 0 and ip != '0.0.0.0' and size != 0:
		result = 'success'
	
	server = get_server_from_file()
	timestamp = time.strftime('%Y-%m-%d %H:%M:%S')

	root_soa_data = {
		'operator': operator,
		'vendor' : vendor,
		'timestamp' : timestamp,
		'data' : {
			'id': node_id,
			'server-id': server_id,
			'ip': server,
			'source': ip,
			'update-date': timestamp,
			'result': result,
			'size': size,
			'soa': soa,
			'delay': delay
		}
	}

	file_name = 'zoneOperation' + '_' + operator + '_' + vendor + '_' + time.strftime('%Y%m%d%H%M%S') + '.gz'
	data = json.dumps(root_soa_data,ensure_ascii=False,indent=4)
	xgj_cache_data_and_upload(file_name,data,'15')


def get_root_copy_soa():
	try:
		dns_query = dns.message.make_query('.', 'SOA')
		res = dns.query.udp(dns_query, '127.0.0.1', port = 53,timeout = 2)
		for i in res.answer:
			for j in i.items:
				return j.serial
	except Exception as e:
		logger.warning('get root copy soa error:'+str(e))
	return 0


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


def get_root_stat_file():
	if os.path.exists(stat_file):
		os.remove(stat_file)
	try:
		subprocess.call([rndc,'stats'])
		shutil.copy(stat_file,root_stat_file)
	except Exception as e:
		logger.error('rndc stats error:'+str(e))
		return False

	return True


def get_querys_from_root_stat_file():
	begin_data = get_stat_data(root_stat_file)
	if begin_data == None:
		logger.warning('gennerate root named begin stat error!')
	
	if get_root_stat_file() == False:
		logger.warning('gennerate root named stat file error!')

	end_data = get_stat_data(root_stat_file)
	if end_data == None:
		logger.warning('gennerate root named end stat error!')
	
	querys = 0
	if 'Incoming-Requests' in begin_data and 'Incoming-Requests' in end_data:
		if 'QUERY' in begin_data['Incoming-Requests'] and 'QUERY' in end_data['Incoming-Requests']:
			querys = end_data['Incoming-Requests']['QUERY'] - begin_data['Incoming-Requests']['QUERY']

	return querys


def get_data_from_named_stat_file():
	begin_data = get_stat_data(tmp_stat_file)
	if begin_data == None:
		logger.warning('gennerate named begin stat error!')
	
	if get_stat_file() == False:
		logger.warning('gennerate named stat file error!')

	end_data = get_stat_data(tmp_stat_file)
	if end_data == None:
		logger.warning('gennerate named end stat error!')
	
	querys = 0
	if 'Incoming-Requests' in begin_data and 'Incoming-Requests' in end_data:
		if 'QUERY' in begin_data['Incoming-Requests'] and 'QUERY' in end_data['Incoming-Requests']:
			querys = end_data['Incoming-Requests']['QUERY'] - begin_data['Incoming-Requests']['QUERY']

	respond,serverfail = 0,0
	if 'Outgoing-Rcodes' in begin_data and 'Outgoing-Rcodes' in end_data:
		respond,serverfail = get_answer(begin_data['Outgoing-Rcodes'],end_data['Outgoing-Rcodes'])
		
	ipv4_req,ipv6_req = 0,0
	if 'Name-Server-Statistics' in begin_data and 'Name-Server-Statistics' in end_data:
		if 'IPv4-requests-received' in begin_data['Name-Server-Statistics'] and 'IPv4-requests-received' in end_data['Name-Server-Statistics']:
			ipv4_req = end_data['Name-Server-Statistics']['IPv4-requests-received'] - begin_data['Name-Server-Statistics']['IPv4-requests-received']
		if 'IPv6-requests-received' in begin_data['Name-Server-Statistics'] and 'IPv6-requests-received' in end_data['Name-Server-Statistics']:
			ipv6_req = end_data['Name-Server-Statistics']['IPv6-requests-received'] - begin_data['Name-Server-Statistics']['IPv6-requests-received']
	
	return querys,respond,respond-serverfail,ipv4_req,ipv6_req


def get_root_copy_top10_and_delay(target_file):
	top,request,respond = {},{},{}

	try:
		with open(target_file,'r') as f:
			for s in f:
				l = s.split(' ')
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
		logger.error('get xgj root copy top10 and delay error'+str(e))

	return [],0


def upload_xgj_root_resolve_data(stat_file):
	beginTime = (datetime.datetime.now() - datetime.timedelta(minutes=5)).strftime('%Y-%m-%d %H:%M:%S')
	endTime = time.strftime('%Y-%m-%d %H:%M:%S')

	querys,respond,noerror,ipv4_request,ipv6_request = get_data_from_named_stat_file()
	top,delay = get_root_copy_top10_and_delay(stat_file)
	
	root_resove_data = {
		'operator': operator,
		'vendor' : vendor,
		"timestamp" : endTime,
		"data" : [
			{
				'id': node_id,
				'server-id': server_id,
				'begin-date': beginTime, 
				'end-date': endTime,
				'qps': querys//300,
				'update-date': endTime,
				'delay': delay,
				'resolution-count': respond,
				'response-success-rate': 0 if querys == 0 else respond*100//querys,
				'resolution-success-rate': 0 if querys == 0 else noerror*100//querys,
				'top10': top
			}
		]
	}
	
	file_name = 'zoneQuery' + '_' + operator + '_' + vendor + '_' + time.strftime('%Y%m%d%H%M%S') + '.gz'
	data = json.dumps(root_resove_data,ensure_ascii=False,indent=4)
	xgj_cache_data_and_upload(file_name,data,'16')


def get_recursion_data(target_file):

	root_copy_list = get_root_copy_list()
	root_ip_list = root_all_ip_list + root_copy_list 

	root_list = root_all_list
	root_list['root_copy'] = root_copy_list

	root_request_stat = {'a':0, 'b':0, 'c':0, 'd':0, 'e':0, 'f':0, 'g':0, 'h':0, 'i':0, 'j':0, 'k':0, 'l':0, 'm':0, 'root_copy':0}
	delay_stat = root_request_stat.copy()
	root_response_stat = root_request_stat.copy()

	root_request,root_response,root_data,request,respond = {},{},{},{},{}

	try:
		with open(target_file,'r') as f:
			for s in f:
				l = s.split(' ')
				root_ip = l[5].split(':')[0]
				dname = l[-1].split('/')[0].split('.')
				if '->' in l:
					k = l[3]+l[5]+l[-1]
					request[k] = int(1000*float(l[1].split(':')[-1]))
					if root_ip in root_ip_list:
						if root_ip in root_request:
							root_request[root_ip] += 1
						else:
							root_request[root_ip] = 1

						if root_ip in root_data:
							root_data[root_ip].append(s)
						else:
							root_data[root_ip] = []
							root_data[root_ip].append(s)
					
				elif '<-' in l:
					k = l[3]+l[5]+l[-1]
					respond[k] = int(1000*float(l[1].split(':')[-1]))
					if root_ip in root_ip_list:
						if root_ip in root_response:
							root_response[root_ip] += 1
						else:
							root_response[root_ip] = 1

						if root_ip in root_data:
							root_data[root_ip].append(s)
						else:
							root_data[root_ip] = []
							root_data[root_ip].append(s)

		for k in root_list:
			count,delay = 0,0
			for ip in root_list[k]:
				if ip in root_request:
					root_request_stat[k] += root_request[ip]
				if ip in root_response:
					root_response_stat[k] += root_response[ip]
				if ip in root_data:
					delay += get_delay(root_data[ip])
					count += 1
			if count > 0:
				delay_stat[k] = delay//count

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

		return root_request_stat, root_response_stat, delay_stat, avg_delay

	except Exception as e:
		logger.error('get recursion data error:'+str(e))

	return root_request_stat, root_response_stat, delay_stat, 0


def upload_xgj_recursion_resolve_data(stat_file):
	beginTime = (datetime.datetime.now() - datetime.timedelta(minutes=5)).strftime('%Y-%m-%d %H:%M:%S')
	endTime = time.strftime('%Y-%m-%d %H:%M:%S')
	t_now = time.strftime('%Y%m%d%H%M%S')

	querys,respond,noerror,ipv4_request,ipv6_request = get_data_from_named_stat_file()
	root_request_stat,root_response_stat,root_delay_stat,avg_delay = get_recursion_data(stat_file)
	root_copy_count = root_request_stat['root_copy']
	root_copy_delay = root_delay_stat['root_copy']
	del root_request_stat['root_copy']
	del root_delay_stat['root_copy']

	recursion_resove_data = {
		'operator': operator,
		'vendor' : vendor,
		'timestamp' : endTime,
		'data' : [
			{
				'id': node_id,
				'server-id': server_id,
				'begin-date': beginTime, 
				'end-date': endTime,
				'update-date': endTime,
				'delay': avg_delay,
				'qps': querys//300,
				'resolution-count-v4': ipv4_request,
				'resolution-count-v6': ipv6_request,
				'response-success-rate': 0 if querys == 0 else respond*100//querys,
				'resolution-success-rate': 0 if querys == 0 else noerror*100//querys,
				'query-7706-count': root_copy_count, 
				'query-7706-delay': root_copy_delay,
				'query-root-count': root_request_stat,
				'query-root-delay': root_delay_stat,
			}
		]
	}
	
	file_name = 'dnsQuery' + '_' + operator + '_' + vendor + '_' + time.strftime('%Y%m%d%H%M%S') + '.gz'
	data = json.dumps(recursion_resove_data,ensure_ascii=False,indent=4)
	xgj_cache_data_and_upload(file_name,data,'14')


def read_dnstap_file(target_file):
	try:
		with open(target_file,'w') as f:
			subprocess.check_call(['dnstap-read',dnstap_file],stdout=f, cwd = '.')
	except Exception as e:
		logger.error('dnstap-read error:'+str(e))


def analysis_data_and_upload():
	stat_file = '/var/drmsd_data/zone.txt'
	loop_count,now_soa,root_soa = 0,0,0

	if os.path.exists(dnstap_file):
		os.remove(dnstap_file)
	if os.path.exists(tmp_dnstap_file):
		os.remove(tmp_dnstap_file)

	if get_stat_file() == False:
		logger.error('start get stat file error!')

	while True:
		if os.path.exists(src_dnstap_file):
			if os.path.exists(tmp_dnstap_file):
				os.rename(tmp_dnstap_file,dnstap_file)
				os.rename(src_dnstap_file,tmp_dnstap_file)
				
				if server_type == 'recursion':
					read_dnstap_file(stat_file)
					upload_xgj_recursion_resolve_data(stat_file)
				elif server_type == 'root_copy':
					read_dnstap_file(stat_file)
					upload_xgj_root_resolve_data(stat_file)
			else:
				os.rename(src_dnstap_file,tmp_dnstap_file)
		
		sleep(1)
		loop_count += 1

		if loop_count % 30 == 0:
			# add there for dig every 60s
			now_soa = get_root_copy_soa()
			print(now_soa)
			if now_soa <= 0:
				logger.warning('dig error please check server named process!!!')
				loop_count = 0
				continue
			if server_type == 'root_copy':
				if root_soa != now_soa:
					root_soa = now_soa
					upload_root_run_data(now_soa)
				if loop_count % 900 == 0 and int(share_delay.value) == 900:
						upload_root_run_data(now_soa)
			if loop_count % 900 == 0:
				loop_count = 0


def restart_dnstap_process():
	try:
		os.system('kill -9 $(pidof fstrm_capture)')
		sleep(1)
		os.system('/usr/bin/start_fstrm_capture -u /var/run/named/dnstap.sock -w /var/named/data/data.dnstap -s 300')
		sleep(1)
	except Exception as e:
		logger.error('kill dnstap process and start dnstap process error: {}'.format(e))


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

	restart_dnstap_process()
	threading._start_new_thread(xgj_main_task,())

	while True:
		p = multiprocessing.Process(target = analysis_data_and_upload, args = ())
		p.start()
		p.join()

	logger.info('main process end at: %s' % time.ctime())
 

