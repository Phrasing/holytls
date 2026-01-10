# h2o Server Setup for Stress Testing

## Requirements

- Linux with cmake, ninja, and OpenSSL dev libraries
- h2o 2.3.0+ (built from source for best performance)

## Installation

```bash
# Install dependencies
sudo apt-get update
sudo apt-get install -y cmake ninja-build libssl-dev pkg-config

# Clone and build h2o
git clone https://github.com/h2o/h2o.git
cd h2o
mkdir build && cd build
cmake -GNinja ..
ninja
sudo ninja install
```

## Setup

```bash
# Create directories
mkdir -p ~/certs ~/www

# Generate self-signed certificate
openssl req -x509 -newkey rsa:2048 -keyout ~/certs/server.key -out ~/certs/server.crt \
  -days 365 -nodes -subj "/CN=localhost"

# Create test file
echo '{"status":"ok"}' > ~/www/test.json

# Create config (update paths for your user)
cat > ~/h2o-multi.conf << 'EOF'
# h2o multi-port config for stress testing
num-threads: 32
http2-idle-timeout: 30

# Listen on 8 ports for multi-reactor testing
listen:
  port: 8443
  ssl:
    certificate-file: certs/server.crt
    key-file: certs/server.key

listen:
  port: 8444
  ssl:
    certificate-file: certs/server.crt
    key-file: certs/server.key

listen:
  port: 8445
  ssl:
    certificate-file: certs/server.crt
    key-file: certs/server.key

listen:
  port: 8446
  ssl:
    certificate-file: certs/server.crt
    key-file: certs/server.key

listen:
  port: 8447
  ssl:
    certificate-file: certs/server.crt
    key-file: certs/server.key

listen:
  port: 8448
  ssl:
    certificate-file: certs/server.crt
    key-file: certs/server.key

listen:
  port: 8449
  ssl:
    certificate-file: certs/server.crt
    key-file: certs/server.key

listen:
  port: 8450
  ssl:
    certificate-file: certs/server.crt
    key-file: certs/server.key

hosts:
  "*":
    paths:
      /:
        file.dir: www
EOF
```

## Running

Run from home directory (where certs/ and www/ are located):

```bash
cd ~
h2o -c h2o-multi.conf
```

## Firewall (GCloud)

```bash
gcloud compute firewall-rules create allow-h2o-stress \
  --allow tcp:8443-8450 \
  --source-ranges 0.0.0.0/0
```
