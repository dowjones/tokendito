#!/bin/ash -ex

chown tokendito:tokendito /home/tokendito/.aws/config /home/tokendito/.aws/credentials /home/tokendito/.config/tokendito/tokendito.ini
su tokendito -c "python tokendito/tokendito.py $*"

