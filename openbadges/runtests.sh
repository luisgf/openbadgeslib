#!/bin/bash

rm private/* >> /dev/null
rm public/* >>/dev/null
/home/luisgf/venv-openbadges/bin/python3 -m unittest discover -s tests/ -v


