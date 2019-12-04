#!/usr/bin/python3
# -*- coding: utf-8 -*-

import time
from log import logger

def upload_task():

	logger.info('upload task start')

	i = 0
	while True:
		time.sleep(1)
		i += 2
		s = 'Upload task number is {}'.format(i)
		#print('upload process:',s)
		logger.info(s)
		
