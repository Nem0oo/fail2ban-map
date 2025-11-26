#!/bin/bash
ip = curl ipinfo.io/ip
touch ../public/places.geojson
touch ./ss_ip.json
python3 ./fail2ban_map.py addserver "$ip"