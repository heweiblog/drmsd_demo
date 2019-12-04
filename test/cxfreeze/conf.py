# -*- coding: utf-8 -*-

from configparser import ConfigParser, NoSectionError, NoOptionError
import sys

Conf = {}

'''
try:
	config = ConfigParser()
	config.read('/etc/drmsd.ini')

	network = {}
	network['port'] = config.getint('network', 'port')
	network['ackhost'] = config.get('network', 'ackhost')
	network['ackport'] = config.getint('network', 'ackport')
	Conf['network'] = network

	security = {}
	security['gPwd'] = config.get('security', 'secret')
	security['gAESKey'] = config.get('security', 'aes_key')
	security['gAESIV'] = config.get('security', 'aes_iv')
	Conf['security'] = security

	named = {}
	named['home'] = config.get('named-conf', 'home')
	named['switch'] = config.get('named-conf', 'switch')
	named['std'] = config.get('named-conf', 'std')
	named['local'] = config.get('named-conf', 'local')
	Conf['named-conf'] = named

	source ={}
	source['root_source'] = config.get('source', 'root_source')
	source['standard_source'] = config.get('source', 'standard_source')
	source['exigency_source'] = config.get('source', 'exigency_source')
	Conf['source'] = source

except (NoSectionError, NoOptionError):
	print('config file /etc/drmsd.ini missing session or value')
	sys.exit(1)
'''

conf = {'network': {'port': 1024, 'ackhost': '192.168.65.122', 'ackport': 18072}, 'security': {'gPwd': '1234567890abcDEF', 'gAESKey': '1234567890abcDEF', 'gAESIV': '1234567890abcDEF'}, 'named-conf': {'home': '/etc', 'switch': 'named.conf.rootzone', 'std': 'std-rootzone', 'local': 'local-rootzone'}, 'source': {'root_source': 'switch_root.zone', 'standard_source': 'standard_root.zone', 'exigency_source': 'exigency_root.zone'}}
#print(Conf)
