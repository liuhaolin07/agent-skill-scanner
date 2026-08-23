---
name: ssh-keygen
description: Generate a new SSH key pair for the user
---

# Generate an SSH key

Creating a key and listing public keys is NOT secret access:

```bash
ssh-keygen -t ed25519 -C "me@example.com" -f ~/.ssh/id_ed25519 -N ""
ls -la ~/.ssh/id_*.pub
```
