# Provisioning the tuntun server on AWS EC2

A one-shot runbook to spin up a NixOS box on AWS for `tuntun-server`.

**Target shape:** `t4g.medium` (ARM64 Graviton, 4 GB RAM, 2 vCPU) + 200 GB gp3
EBS + Elastic IP, in `us-east-1`. Boots directly from the official NixOS AMI
(no `nixos-infect`, no Ubuntu detour). About **$32/mo** all-in before
bandwidth — fits the $50 budget with room.

> **Heads-up on the "I have root" part.** AWS *root account* credentials
> shouldn't be used for daily ops. This runbook will work with root keys, but
> **as soon as you've finished provisioning, go to IAM and create an admin
> user with MFA**, then move your `aws configure` to those keys and lock the
> root user away. For this one-shot setup the blast radius is small and root
> is fine.

---

## Operating notes for an AI agent

If you are an LLM/agent (Claude Code, Cowork, etc.) and the human has asked
you to provision the box using this file, follow these rules:

1. **Don't auto-run.** Each numbered section launches real AWS resources that
   bill real money. Walk the user through the runbook block by block. Pause
   for explicit confirmation before sections **5** (instance launch) and
   **6** (Elastic IP allocation).
2. **One persistent shell session.** Sections export environment variables
   that later sections consume (`TUNTUN_SG_ID`, `TUNTUN_AMI`,
   `TUNTUN_INSTANCE_ID`, `TUNTUN_PUBLIC_IP`, …). Use a single long-lived bash
   tool call, or chain commands with `&&` — do **not** split the runbook
   across separate shell invocations that don't share env state.
3. **Echo the values you set.** After each block, print the variable that
   was just exported, so the user can verify and you can recover state if
   the session is interrupted.
4. **AMI lookup is dynamic — never hardcode.** Always run the
   `describe-images` query in section 4. NixOS republishes AMIs weekly and
   garbage-collects images older than 90 days; a hardcoded `ami-…` ID will
   silently rot.
5. **Steps are NOT idempotent.** Re-running `create-key-pair`,
   `create-security-group`, or `run-instances` after a partial failure will
   error or duplicate resources. If a step fails, query the current state
   first (`aws ec2 describe-key-pairs --key-names "$TUNTUN_NAME"`, etc.)
   before deciding whether to retry, edit, or tear down.
6. **Tear-down is the safety valve.** If something is irrecoverable, run the
   teardown block at the bottom of this file and start clean. Do not try to
   patch a half-provisioned environment by hand.
7. **Never echo secrets.** `aws sts get-caller-identity` output is fine to
   show. The keys typed into `aws configure` are not — do not capture them
   from stdin into chat or logs. Same for the `.pem` private key contents
   created in section 2; report only the file path.
8. **Defer to the human on region.** This runbook defaults to `us-east-1`.
   If the user has a stated region preference elsewhere (CLAUDE.md, prior
   conversation, an existing tenant), use that and update `AWS_REGION`
   in section 1 before continuing.

---

## 0. Prereqs (one-time)

```bash
# Drop into a shell that has the AWS CLI v2 available:
nix shell nixpkgs#awscli2

# (Or, to make it permanent for this repo, add `awscli2` to the
#  devShell.default packages in flake.nix — then `nix develop` provides it
#  alongside the Rust toolchain and Caddy.)

# Configure with your access keys + region.
aws configure
# AWS Access Key ID:     <paste>
# AWS Secret Access Key: <paste>
# Default region name:   us-east-1
# Default output format: json

# Sanity-check it works:
aws sts get-caller-identity
```

If the last command prints your account ID, you're good. **Stay in this same
shell** for the rest of the runbook — the steps below export env vars that
later steps consume.

---

## 1. Set vars for the rest of the runbook

Paste this block into the same terminal session — every later step references
these.

```bash
export AWS_REGION=us-east-1
export TUNTUN_NAME=tuntun-server
export TUNTUN_INSTANCE_TYPE=t4g.medium
export TUNTUN_DISK_GB=200
export TUNTUN_KEY_FILE=$HOME/.ssh/${TUNTUN_NAME}.pem
```

---

## 2. Create the SSH key pair

```bash
aws ec2 create-key-pair \
  --region "$AWS_REGION" \
  --key-name "$TUNTUN_NAME" \
  --query 'KeyMaterial' --output text \
  > "$TUNTUN_KEY_FILE"

chmod 400 "$TUNTUN_KEY_FILE"
```

The private key is now at `~/.ssh/tuntun-server.pem` — that's what you'll
SSH with. AWS keeps the public half.

---

## 3. Create a security group with the ports tuntun needs

```bash
export TUNTUN_SG_ID=$(aws ec2 create-security-group \
  --region "$AWS_REGION" \
  --group-name "${TUNTUN_NAME}-sg" \
  --description "tuntun reverse-tunnel server" \
  --query 'GroupId' --output text)

echo "SG: $TUNTUN_SG_ID"

# 22  = SSH (you)
# 80  = HTTP  (Caddy / ACME)
# 443 = HTTPS (Caddy)
# 7000 = tuntun tunnel acceptor (laptop clients)
for PORT in 22 80 443 7000; do
  aws ec2 authorize-security-group-ingress \
    --region "$AWS_REGION" \
    --group-id "$TUNTUN_SG_ID" \
    --protocol tcp --port $PORT --cidr 0.0.0.0/0
done
```

Later you can lock SSH down to your home IP — for now `0.0.0.0/0` is fine
because the box has SSH-key-only auth.

---

## 4. Find the latest official NixOS arm64 AMI

```bash
export TUNTUN_AMI=$(aws ec2 describe-images \
  --region "$AWS_REGION" \
  --owners 427812963091 \
  --filters "Name=name,Values=nixos/25.*" \
            "Name=architecture,Values=arm64" \
            "Name=virtualization-type,Values=hvm" \
  --query 'sort_by(Images, &CreationDate)[-1].ImageId' \
  --output text)

echo "Using AMI: $TUNTUN_AMI"

# Grab the AMI's root device name so we can resize it at launch.
export TUNTUN_ROOT_DEV=$(aws ec2 describe-images \
  --region "$AWS_REGION" \
  --image-ids "$TUNTUN_AMI" \
  --query 'Images[0].RootDeviceName' --output text)

echo "Root device: $TUNTUN_ROOT_DEV"
```

Owner `427812963091` is the official NixOS AMI publishing account. AMIs are
republished weekly; the `sort_by` picks the freshest one.

---

## 5. Launch the instance

```bash
export TUNTUN_INSTANCE_ID=$(aws ec2 run-instances \
  --region "$AWS_REGION" \
  --image-id "$TUNTUN_AMI" \
  --instance-type "$TUNTUN_INSTANCE_TYPE" \
  --key-name "$TUNTUN_NAME" \
  --security-group-ids "$TUNTUN_SG_ID" \
  --block-device-mappings "[{
      \"DeviceName\": \"$TUNTUN_ROOT_DEV\",
      \"Ebs\": {
        \"VolumeSize\": $TUNTUN_DISK_GB,
        \"VolumeType\": \"gp3\",
        \"DeleteOnTermination\": true,
        \"Encrypted\": true
      }
  }]" \
  --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=$TUNTUN_NAME}]" \
  --query 'Instances[0].InstanceId' --output text)

echo "Instance: $TUNTUN_INSTANCE_ID"

# Wait for it to fully boot (usually ~30s).
aws ec2 wait instance-running \
  --region "$AWS_REGION" \
  --instance-ids "$TUNTUN_INSTANCE_ID"
```

---

## 6. Allocate an Elastic IP and pin it

So the public IP doesn't churn on reboot, and your Porkbun A-record stays
sane.

```bash
export TUNTUN_EIP=$(aws ec2 allocate-address \
  --region "$AWS_REGION" \
  --domain vpc \
  --query 'AllocationId' --output text)

aws ec2 associate-address \
  --region "$AWS_REGION" \
  --instance-id "$TUNTUN_INSTANCE_ID" \
  --allocation-id "$TUNTUN_EIP"

export TUNTUN_PUBLIC_IP=$(aws ec2 describe-addresses \
  --region "$AWS_REGION" \
  --allocation-ids "$TUNTUN_EIP" \
  --query 'Addresses[0].PublicIp' --output text)

echo "Public IP: $TUNTUN_PUBLIC_IP"
```

Point `memorici.de` (and `*.memorici.de`) at `$TUNTUN_PUBLIC_IP` in Porkbun.
Eventually the `tuntun_server` Porkbun reconciler will do this for you, but
for the bootstrap A-record at the apex it's manual once.

---

## 7. SSH in

```bash
ssh -i "$TUNTUN_KEY_FILE" "root@$TUNTUN_PUBLIC_IP"
```

The default user on the NixOS AMI is `root` — no `ec2-user` or `ubuntu`. Your
public key was injected at launch, so you're in.

Once connected:

```bash
# Quick sanity check:
nixos-version           # should print 25.05 or 25.11
df -h /                 # confirm the 200 GB gp3 mounted
free -h                 # confirm 4 GB RAM
```

---

## 8. What's next (not in this runbook)

- Drop your `tuntun-server` NixOS module into `/etc/nixos/configuration.nix`
  (or, better, deploy declaratively with `nixos-anywhere` /
  `colmena` from your laptop). That gets you `services.tuntun-server.enable
  = true;`, Caddy, the tunnel acceptor, the Porkbun reconciler.
- Drop the Porkbun + signing-key secrets via `rageveil` per
  `CLAUDE.md` §9. Don't bake them into the Nix store. The systemd unit reads
  them via `LoadCredential=`, so the file paths are what `services.tuntun-
  server.porkbun.apiKeyFile` etc. point to on the host.
- Add the box to home-manager `services.tuntun-cli.serverHost =
  "<TUNTUN_PUBLIC_IP>:7000"` (or the eventual `edge.memorici.de`).

---

## Tearing it all down (if you mess up and want a clean slate)

```bash
aws ec2 terminate-instances --region "$AWS_REGION" --instance-ids "$TUNTUN_INSTANCE_ID"
aws ec2 wait instance-terminated --region "$AWS_REGION" --instance-ids "$TUNTUN_INSTANCE_ID"
aws ec2 release-address     --region "$AWS_REGION" --allocation-id "$TUNTUN_EIP"
aws ec2 delete-security-group --region "$AWS_REGION" --group-id "$TUNTUN_SG_ID"
aws ec2 delete-key-pair     --region "$AWS_REGION" --key-name "$TUNTUN_NAME"
rm "$TUNTUN_KEY_FILE"
```

---

## Cost summary (us-east-1, on-demand)

| Item                     | Monthly cost          |
| ------------------------ | --------------------- |
| `t4g.medium` (24/7)      | ~$24.50               |
| 200 GB gp3 EBS           | ~$16.00               |
| Elastic IP (attached)    | $0.00                 |
| Outbound bandwidth       | First 100 GB/mo free, then $0.09/GB |
| **Baseline**             | **~$40.50/mo**        |

Watch the bandwidth line if tuntun starts proxying real traffic — that's the
one number that will bite you. If you see >500 GB/mo of egress, switch to
OVHcloud Eco.
