# VulnScan

## Install

### tl;dr
```bash
sudo apt update
sudo apt upgrade -y

source .env

# Install Elastic

# Install Nessus
curl --request GET \
  --url 'https://www.tenable.com/downloads/api/v2/pages/nessus/files/Nessus-10.7.3-ubuntu1404_amd64.deb' \
  --output 'Nessus-10.7.2-ubuntu1404_amd64.deb'
sudo dpkg -i Nessus-10.7.2-ubuntu1404_amd64.deb
sudo rm Nessus-10.7.2-ubuntu1404_amd64.deb
sudo systemctl enable nessusd.service
sudo systemctl start nessusd.service
sudo /opt/nessus/sbin/nessuscli fetch --register $ACTIVATION_CODE
sudo /opt/nessus/sbin/nessuscli adduser # input required
```

Now login to Nessus and fetch the API-Key and -Secret. Place it in `.env`.

Also place the API-Key for Elastic in `.env`.

### Detailed installation
tbd

## Register the license

```bash
source .env
sudo /opt/nessus/sbin/nessuscli fetch --register $ACTIVATION_CODE
```

## Update

```bash
source .env
sudo /opt/nessus/sbin/nessuscli update --plugins-only
```
