#! /bin/sh
set -e
apt install -y python3.12-venv clickhouse-server

rm -rf .venv
python3 -m venv .venv
. .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

pre-commit install
pre-commit autoupdate

git config blame.ignoreRevsFile .git-blame-ignore-revs
