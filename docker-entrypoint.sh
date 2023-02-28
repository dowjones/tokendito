#!/bin/ash -e

files="/home/tokendito/.aws/config /home/tokendito/.aws/credentials /home/tokendito/.config/tokendito/tokendito.ini"
stat -c "chown %u:%g %n" $files > /tmp/$$.restore
chown tokendito:tokendito $files
su tokendito -c "python tokendito/tokendito.py $*"
. /tmp/$$.restore
