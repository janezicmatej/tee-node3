# Create TDX instance

```bash
gcloud compute instances create cvm-attestation-test \
    --machine-type=c3-standard-4 \
    --min-cpu-platform="Intel Sapphire Rapids" \
    --zone=us-central1-a \
    --confidential-compute-type="TDX" \
    --maintenance-policy=TERMINATE \
    --image=ubuntu-2404-noble-amd64-v20241219 \
    --image-project=ubuntu-os-cloud \
    --scopes https://www.googleapis.com/auth/cloud-platform \
    --service-account=confidential-sa@flare-network-sandbox.iam.gserviceaccount.com
```

```bash
gcloud compute ssh cvm-attestation-test
```

# Install go

```bash
wget https://go.dev/dl/go1.22.0.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.22.0.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin
```

# Install gotpm

```bash
git clone https://github.com/google/go-tpm-tools.git --depth 1
cd go-tpm-tools/cmd/gotpm/
go build
```

# Generate and verfy attestation

```bash
nonce=$(head -c 16 /dev/urandom | xxd -p)
sudo ./gotpm attest --nonce $nonce --format textproto --output quote.dat
sudo ./gotpm verify debug --nonce $nonce --format textproto --input quote.dat --output vtpm_report
```
