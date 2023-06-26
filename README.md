# SibylGithubDataConnector

## Setup

### Environment 

- Ubuntu 20.04 with Linux Kernel ≥ 5.11
- CPU: Intel Xeon E-2288G
- Docker (>= 20.10.21) & Docker-Compose

### Prepare SSH keys

To access Github private repository in Dockerfile, you need to configure the SSH keys: 

```bash
# do not enter passphrase
ssh-keygen -t ed25519 -C "your_email@example.com"
eval "$(ssh-agent -s)"
ssh-add ~/.ssh/id_ed25519
cp ~/.ssh/id_ed25519 .
```

Then add the content in `~/.ssh/id_ed25519.pub` to [Github SSH keys](https://github.com/settings/keys) by clicking `New SSH keys` button.

### Prepare cert files

To establish a TLS channel, we need a CA and generates a client cert for mutual authentication, store them at `cert` directory.

* Generate Client private key:
 
  ```bash
  openssl ecparam -genkey -name prime256v1 -out cert/client.key
  ```

* Export the keys to pkcs8 unencrypted format 
  
  ```bash
  openssl pkcs8 -topk8 -nocrypt -in cert/client.key -out cert/client.pkcs8
  ```

* Generate Client CSR 
  
  ```bash
  openssl req -new -SHA256 -key cert/client.key -nodes -out cert/client.csr
  ```

* Generate Client Cert 

  ```bash
  openssl x509 -req -extfile <(printf "subjectAltName=DNS:localhost,DNS:www.example.com") -days 3650 -in cert/client.csr -CA cert/ca.crt -CAkey cert/ca.key -CAcreateserial -out cert/client.crt
  ```

### Pull Docker images

* `clique/sibyl-service`
* `clique/sibyl-mtls-service`
* `clique/sibyl-dcsv2-service`
* `clique/sibyl-dcsv2-mtls-service`

## Build & Deploy

* Build Sibyl: 

  ```bash
  docker build -t sibyl -f Dockerfile.sibyl .
  ```

* Build Sibyl with mTLS: 

  ```bash
  docker build -t sibyl -f Dockerfile.mTLS.sibyl .
  ```

* Build DCsv2 Sibyl:

  ```bash
  docker build -t sibyl -f Dockerfile.DCsv2.sibyl .
  ```

* Build DCsv2 Sibyl with mTLS:

  ```bash
  docker build -t sibyl -f Dockerfile.DCsv2.mTLS.sibyl .
  ```

* Build DCsv2 custom DCAP service:

  ```bash
  docker build -t pccs -f Dockerfile.DCsv2.pccs .
  ```

* Deploy Sibyl:

  ```bash
  docker compose -f docker-compose.yml up
  ```

* Deploy Sibyl with custom DCAP service:

  ```bash
  docker compose -f docker-compose-dcap.yml up
  ```

Then Sibyl will run and listen on port 3443.

> For Azure VMs, custom DCAP service is only avaiable for DCsv2 and is not supported in DCsv3.

## Test

```bash
curl -k --location 'https://localhost:3443/query' --key ./cert/client.pkcs8 --cert ./cert/client.crt \
--header 'Content-Type: application/json' \
--data '{
    "query_type": "github_get_rsa_public_key"
}'
```