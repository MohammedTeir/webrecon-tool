#!/bin/bash

# Default wordlists for the tool
mkdir -p /home/ubuntu/webrecon-tool/wordlists

# Create a simple subdomain wordlist
cat > /home/ubuntu/webrecon-tool/wordlists/subdomains.txt << EOF
www
mail
webmail
admin
blog
shop
dev
test
staging
api
app
m
mobile
secure
vpn
cdn
media
img
images
static
docs
support
help
ftp
ns1
ns2
ns3
portal
intranet
EOF

# Create a simple directory wordlist
cat > /home/ubuntu/webrecon-tool/wordlists/directories.txt << EOF
admin
wp-admin
administrator
login
wp-login.php
admin.php
adminlogin
admin/login
admin/index.php
user/login
dashboard
cpanel
phpmyadmin
webmail
wp-content
wp-includes
images
img
css
js
static
media
upload
uploads
files
backup
backups
data
logs
log
temp
tmp
cache
.git
.svn
.env
robots.txt
sitemap.xml
config
configuration
setup
install
readme
README.md
LICENSE
api
v1
v2
docs
documentation
EOF

echo "Default wordlists created in /home/ubuntu/webrecon-tool/wordlists/"
