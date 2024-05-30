import re
import subprocess
import json
import os
import logging
from flask import Flask, jsonify, request
from flask_cors import CORS
from logging.config import dictConfig
import asyncio
from urllib.request import Request, urlopen
import urllib
import requests
from termcolor import colored
from urllib.parse import urlparse
import random
import urllib.error
import time
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.common.exceptions import NoSuchElementException
from bs4 import BeautifulSoup
from requests.exceptions import ConnectionError

def run_subprocess(command):
    try:
        return subprocess.run(command, capture_output=True, text=True, check=True, encoding='utf-8')
    except subprocess.CalledProcessError as e:
        logging.error(f"Subprocess {command} failed with {e}")
        return None

def read_wayback_urls(filename):
    with open(filename, "r") as f:
        wayback_data = f.read().splitlines()
    return wayback_data

def execute_cors_scanner(filename):
    cors_result = {}
    with open(filename, "r") as f:
        subdomain_list = f.read().splitlines()
    for u in subdomain_list:
        ret = subprocess.run(["cors", "-u", u], stdout=subprocess.PIPE)
        cors_result[u] = ret.stdout.decode('utf-8').strip()
    return cors_result