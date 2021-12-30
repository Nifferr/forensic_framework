#!/bin/sh
###################################################
# Install all manner of forensics tools 
# on Ubuntu 
###################################################

###################################################
# Disk Image tools 
###################################################
sudo apt-get -y install xmount
sudo apt-get -y install virtualbox
sudo apt-get -y install virtualbox-fuse
sudo apt-get -y install afflib-tools
sudo apt-get -y install libfuse-dev 
sudo apt-get -y install fuse-utils
sudo echo "user_allow_other" >> /etc/fuse.conf
sudo chmod 644 /etc/fuse.conf

###################################################
# Install log2timeline
###################################################
wget https://log2timeline.googlecode.com/files/log2timeline_0.65.tgz
OR
sudo nano -w /etc/apt/sources.list
deb http://log2timeline.net/pub/ lucid main
wget -q http://log2timeline.net/gpg.asc -O- | sudo apt-key add -
sudo apt-get update
sudo apt-get install log2timeline-perl

###################################################
# Vinetto is a forensics tool to examine Thumbs.db files
###################################################
sudo apt-get install vinetto

###################################################
# Install pasco
# for Recovering IE History
###################################################
sudo apt-get install pasco

###################################################
#  Perl script to parse a shortcut (LNK) file and retrieve data
###################################################
svn checkout http://jaygeeplayground.googlecode.com/svn/trunk/ lslink

###################################################
# Regripper 
###################################################
perl -MCPAN -e 'install Parse::Win32Registry'
sudo mkdir -p /opt/regripper
cd /opt/regripper
sudo wget https://regripper.googlecode.com/files/rrv2.5.zip
sudo unzip rrv2.5.zip

sudo mkdir -p /opt/regripper/plugins
cd /opt/regripper/plugins
sudo wget https://regripperplugins.googlecode.com/files/regripperplugins_20130218.zip
sudo unzip regripperplugins_20130218.zip
cd ..
	
# Shell script which makes rip.pl run on Linux (riplin.pl)
# Fix end of line
sudo cat rip.pl | sed 's|\r$||g' > /tmp/riplin0.pl
# Now fix the first line so linux perl executed
sudo cat /tmp/riplin0.pl | sed "s| c:\\\\perl\\\\bin\\\\perl.exe|`which perl`|" > /tmp/riplin1.pl
# Fix the backslash before the plugins directory
sudo cat /tmp/riplin1.pl | sed 's|plugins\\\\|plugins/|' > riplin.pl
# Make executable
sudo chmod +x riplin.pl