#-*- coding: utf-8 -*- 

import json
from flask import Flask
from flask import request
import traceback
import time
import random,string
import base64, hashlib, zlib
from Crypto.Cipher import AES
from copy import deepcopy
from requests.packages import urllib3
import threading
from time import sleep
import uuid
import requests

from public import *

#去掉request post的警告
urllib3.disable_warnings()

gRuleDict   = None
gConfDict   = None
logger         = None
gPwd        = '1234567890abcDEF'
gMsgAuthKey = '1234567890abcDEF'
gAESKey     = b'1234567890abcDEF'
gAESIV      = b'1234567890abcDEF'

app = Flask(__name__)


#返回给drms的ack
def waj_dnsCommandAck(uuid, orgId, subsysId, hashMode, compressMode, encryptMode):
	sleep(1)
	try:
		url                 = 'http://'+ackhost+':'+ackhost+'/'+'41'+'/'+orgId
		randVal             = bytes(''.join(random.sample(string.ascii_letters, 20)), 'utf-8')
		lPwd                = bytes(waj_conf['security']['user_pwd'], 'utf-8')
		lMsgAuthKey         = bytes(waj_conf['security']['data_pwd'], 'utf-8')
		commandVersion      = 'v0.1'
		_uuid               = uuid
        
		jsonData = {
			'cmdUuid'       : str(_uuid),
			'processStatus' : '5',
			'remark'        : '指令处置完毕',
			'workCompRate'  : 0.99,
			'timeStamp'     : time.strftime("%Y-%m-%dT%H:%M:%SZ", time.localtime())
		}
        
		data                = bytes(json.dumps(jsonData),'utf-8')   
        
		if hashMode == '0':  
			_hashed_pwd = (lPwd + randVal)
			pwdHash = base64.b64encode(_hashed_pwd)
		elif hashMode == '1':  
			_hashed_pwd = hashlib.md5(lPwd + randVal).hexdigest()
			pwdHash = base64.b64encode(_hashed_pwd.encode('utf-8'))
		elif hashMode == '2':  
			_hashed_pwd = hashlib.sha1(lPwd + randVal).hexdigest()
			pwdHash = base64.b64encode(_hashed_pwd.encode('utf-8'))
		elif hashMode == '3':  
			_hashed_pwd = hashlib.sha256(lPwd + randVal).hexdigest()
			pwdHash = base64.b64encode(_hashed_pwd.encode('utf-8'))
		elif hashMode == '11': pass
		else :  
			_hashed_pwd = lPwd + randVal
			pwdHash = base64.b64encode(_hashed_pwd)

		if compressMode == '0': _compressed_data = data
		elif compressMode == '1': _compressed_data = zlib.compress(data)

		if encryptMode == '0':
			_encrypted_data = _compressed_data
		elif encryptMode == '1':
			e = AESCipher(waj_conf['security']['aes_key'].encode('utf-8'), waj_conf['security']['aes_iv'].encode('utf-8'))
			_encrypted_data = e.encrypt(_compressed_data)
		elif encryptMode == '2'   : pass
		elif encryptMode == '11'  : pass
		elif encryptMode == '12'  : pass
		elif encryptMode == '13'  : pass
		elif encryptMode == '14'  : pass
		else: _encrypted_data = _compressed_data
                   
		data = base64.b64encode(_encrypted_data)

		if hashMode == '0':  
			_hashed_data = _compressed_data + lMsgAuthKey
			dataHash = base64.b64encode(_hashed_data)
		elif hashMode == '1':  
			_hashed_data = hashlib.md5(_compressed_data + lMsgAuthKey).hexdigest()
			dataHash = base64.b64encode(_hashed_data.encode('utf-8'))
		elif hashMode == '2':  
			_hashed_data = hashlib.sha1(_compressed_data + lMsgAuthKey).hexdigest()
			dataHash = base64.b64encode(_hashed_data.encode('utf-8'))
		elif hashMode == '3':  
			_hashed_data = hashlib.sha256(_compressed_data + lMsgAuthKey).hexdigest()
			dataHash = base64.b64encode(_hashed_data.encode('utf-8'))
		elif hashMode == '11': pass
		else :  
			_hashed_data = _compressed_data + lMsgAuthKey
			dataHash = base64.b64encode(_hashed_data)

		requestData = {
			'uuid'          : str(_uuid),
			'orgId'         : orgId,
			'subsysId'      : subsysId,
			'intfId'        : '41',
			'intfVer'       : commandVersion,
			'timeStamp'     : time.strftime("%Y-%m-%dT%H:%M:%SZ", time.localtime()),
			'randVal'       : randVal.decode(),
			'pwdHash'       : pwdHash.decode(),
			'encryptMode'   : encryptMode,
			'hashMode'      : hashMode,
			'compressMode'  : compressMode,
			'dataTag'       : '0',
			'data'          : data.decode(),
			'dataHash'      : dataHash.decode()
		}
        
		headers = {
			"Accept-Charset": "utf-8",
			"Content-Type": "application/json"
		}   

		ret =requests.post(url, json.dumps(requestData), headers = headers)
		retData = json.loads(ret.text)
        
		if retData.get('errorCode') == '0':
			logger.info('send to {} waj_dnsCommandAck success'.format(url))
		else:
			logger.info('send to {} waj_dnsCommandAck error'.format(url))

	except Exception as e:
		logger.error('send to {} waj_dnsCommandAck failed:{}'.format(url,e))



#获取返回错误的信息
def gen_waj_Result(rcode, uuid = ' ', orgId ='4', subsysId = '20', hashMode='3', compressMode='1', encryptMode='0'):
	lookaside = {    
		'0' : '',    
		'1' : 'Failure for unknown reason',    
		'2' : 'Certification error',    
		'3' : 'Check failure',    
		'4' : 'De-compression error',    
		'5' : 'Format error',    
	}   
	result = {
		"errorCode"         : rcode,
		"errorMsg"          : lookaside[rcode],
		"timeStamp"         : time.strftime("%Y-%m-%dT%H:%M:%SZ", time.localtime())
	}
	if rcode == '0':
		threading._start_new_thread(waj_dnsCommandAck, (uuid, orgId, subsysId, hashMode, compressMode, encryptMode))
	return result


def waj_certificate(pwdHash, randVal, hashMode):
	gPwd = waj_conf['security']['user_pwd']
	if hashMode   == '0'     : raw = (gPwd + randVal).encode('utf-8')
	elif hashMode == '1'     : raw = hashlib.md5((gPwd + randVal).encode()).hexdigest().encode('utf-8')
	elif hashMode == '2'     : raw = hashlib.sha1((gPwd + randVal).encode()).hexdigest().encode('utf-8')
	elif hashMode == '3'     : raw = hashlib.sha256((gPwd + randVal).encode()).hexdigest().encode('utf-8')
	elif hashMode == '11'    : pass 
	else: return False
    
	return pwdHash == base64.b64encode(raw).decode('utf-8')


def waj_deCMDPre(data, compressMode, dataHash,hashMode, encryptMode):
	gAESKey, gMsgAuthKey = waj_conf['security']['aes_key'],waj_conf['security']['data_pwd']
	raw = base64.b64decode(data.encode('utf-8'))

	if encryptMode == '0'     : aesData = raw
	elif (gAESKey is not None) and (encryptMode == '1'): aesData = aesDecode(raw)
	elif encryptMode == '2'   : pass
	elif encryptMode == '11'  : pass
	elif encryptMode == '12'  : pass
	elif encryptMode == '13'  : pass
	elif encryptMode == '14'  : pass
	else: return None
    
	if hashMode == '0'      : hashed = aesData + gMsgAuthKey.encode('utf-8')
	elif hashMode == '1'    : hashed = hashlib.md5((aesData + gMsgAuthKey.encode('utf-8'))).hexdigest().encode('utf-8')
	elif hashMode == '2'    : hashed = hashlib.sha1((aesData + gMsgAuthKey.encode('utf-8'))).hexdigest().encode('utf-8')
	elif hashMode == '3'    : hashed = hashlib.sha256((aesData + gMsgAuthKey.encode('utf-8'))).hexdigest().encode('utf-8')
	elif hashMode == '11'   : pass 
	else: return None
  
	if base64.b64encode(hashed).decode('utf-8') != dataHash:
		return None
    
	if compressMode == '0'      : requestData = aesData
	elif compressMode == '1'    : requestData = zlib.decompress(aesData)
    
	return requestData


def clear_zone_cache(domain,domainType):
	try:
		if domainType == '1':
			subprocess.check_call(['rndc', 'flushname', domain], cwd = '/etc')
			logger.info('clear domain {} cache'.format(domain))
		elif domainType == '0' or domainType == '2':
			subprocess.check_call(['rndc', 'flushtree', domain], cwd = '/etc')
			logger.info('clear zone {} all cache'.format(domain))
		return True
	except subprocess.CalledProcessError:
		logger.error('rndc flush {} error!'.format(domain))
	return False
	


def waj_clear_cache(requestData, orgId, subsysId, uuid, encryptMode, hashMode, compressMode):
	try:
		jsonData        = json.loads(requestData.decode("utf-8"))
		domain          = jsonData.get('domain')
		domainType      = jsonData.get('domainType')
		if clear_zone_cache(domain,domainType):
			return json.dumps(gen_waj_Result('0',uuid, orgId, subsysId, hashMode, compressMode, encryptMode))
	except Exception as e:
		logger.error('clear cache error: {}'.format(e))
	return json.dumps(gen_waj_Result('1'))


#flask 处理https的入口函数
@app.route('/<int:intfId>/<int:orgId>', methods=['POST'])
def handerHttpsRequest(intfId, orgId):
	try:
		if request.method == 'POST':
			requestData            = request.get_data()
			jsonData       = json.loads(requestData.decode("utf-8"))			
			logger.info('local 0.0.0.0:18899 HttpsRequest recv {}'.format(jsonData))            
            #获取请求参数里面的对应值            
			uuid            = jsonData.get("uuid")            
			orgId           = jsonData.get("orgId")            
			subsysId        = jsonData.get("subsysId")            
			intfId          = jsonData.get("intfId")            
			intfVer         = jsonData.get("intfVer")            
			timeStamp       = jsonData.get('timeStamp')            
			randVal         = jsonData.get('randVal')            
			pwdHash         = jsonData.get('pwdHash')            
			encryptMode     = jsonData.get('encryptMode')            
			hashMode        = jsonData.get('hashMode')            
			compressMode    = jsonData.get('compressMode')            
			dataTag         = jsonData.get('dataTag')            
			data            = jsonData.get('data')            
			dataHash        = jsonData.get('dataHash')                        
			#进行hash的验证            
			if not waj_certificate(pwdHash, randVal, hashMode):                
				logger.error('waj Certification error')                
				return json.dumps(gen_waj_Result('2'))            
			#数据的提取和校验            
			requestData = waj_deCMDPre(data, compressMode, dataHash,hashMode, encryptMode)            
			if not requestData:                
				logger.error('waj Check data failure')                
				return json.dumps(gen_waj_Result('3'))

			command_func = {'29':waj_clear_cache}
			if intfId in command_func:
				return command_func[intfId](requestData, orgId, subsysId, uuid, encryptMode, hashMode, compressMode)            
			#不支持的inftid            
			else:                
				logger.warning('unsupported intfId : {} \nrequestData : {}'.format(intfId,requestData))        
		return json.dumps(gen_waj_Result('5'))    
	except Exception as e:        
		logger.warning('waj ack catch exception : {}'.format(e))        
		return json.dumps(gen_waj_Result('1'))


def waj_main_task():
	app.run(host='0.0.0.0', port=waj_conf['net']['port'], debug=False, ssl_context=(waj_conf['net']['crt'], waj_conf['net']['key']))
