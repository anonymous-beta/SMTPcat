#!/bin/bash
python3 smtpcat.py "$1" --full --workers 20 --nmap --tls
