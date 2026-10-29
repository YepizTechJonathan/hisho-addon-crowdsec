# Changelog

## 0.2.0

- Find it: the page lists CrowdSec containers (any name, image `crowdsecurity/crowdsec`) on the servers the Servers (SSH) add-on knows, one quick `docker ps` per server (`sudo -n` where the server says so); Use this fills in server and container. Installs already added and servers that don't answer aren't listed.

## 0.1.2

- Every field on its setup form says in plain words what it is, and links to where to get it (addon.yaml `help:`, shown by Hisho's dashboard).
- Any server Hisho reaches over SSH counts, on your home network or the internet (the example no longer suggests an offsite one).

## 0.1.1

- README says what you need (addon.yaml you_need) and how to use it; the README check requires both.

## 0.1.0

- Moved out of Hisho into its own repository (hisho-addon-crowdsec); installed from the add-on store.

