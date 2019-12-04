#!/usr/bin/python3
# -*- coding: utf-8 -*-

import logging,logging.handlers

logger = logging.getLogger('main')
logger.setLevel(level = logging.INFO)
handler = logging.FileHandler("/tmp/main.log")
handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)
