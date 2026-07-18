# PyTorch-nightly Dependency Confusion Attack — Python Supply Chain

## 📅 When Did It Happen?
December 25-30, 2022 (attack window), December 30, 2022 (discovery and public disclosure)

## 🎯 Target System
PyTorch-nightly Linux packages (installed via pip). A dependency called torchtriton was poisoned via the Python Package Index (PyPI).

## 🔴 What Happened?
**Dependency confusion** attack:

A dependency of PyTorch-nightly, `torchtriton`, was normally downloaded from PyTorch's official package index (`download.pytorch.org/whl/nightly`). However:

1. A "security researcher" (self-proclaimed) published a malicious package on PyPI with the same name (`torchtriton`) and a higher version number
2. Since PyPI comes before custom indexes in pip's priority order, the malicious version was automatically downloaded to users' systems
3. The malicious package contained code in `__init__.py` that executed a triton binary
4. This binary collected sensitive system information and exfiltrated it encrypted over DNS

## 🧠 Root Cause
1. **Dependency confusion attack**: Since PyPI comes before custom indexes, if a package with the same name exists on PyPI, pip downloads it first
2. **pip's priority order** (`--index-url` vs PyPI): pip checks PyPI before custom indexes when `--extra-index-url` is used
3. **Automatic dependency resolution**: developers unknowingly downloaded the malicious package

## 💥 Impact
- **Thousands** of developers downloaded the malicious package (exact number unknown)
- Stolen data:
  - `/etc/hosts`, `/etc/passwd` files
  - `$HOME/.gitconfig`
  - `$HOME/.ssh/*` (SSH keys)
  - Environment variables
  - First 1000 files (`$HOME/*`)
  - System information (hostname, username, working directory)
- Data was exfiltrated encrypted over DNS to the `h4ck[.]cfd` domain
- The binary (`triton`) that exfiltrated data was detected on VirusTotal

## 🔧 How Was It Fixed?
- PyTorch team published an urgent warning (December 31, 2022)
- The torchtriton dependency was removed and replaced with `pytorch-triton`
- A dummy (empty) package was registered on PyPI for `torchtriton` (to prevent recurrence)
- All nightly packages were temporarily removed
- PyPI security team was contacted
- Users were advised to run `pip3 uninstall torch torchvision torchaudio torchtriton`

## 🎓 Lessons Learned
1. **Dependency confusion attacks** — if you have custom package indexes, also reserve dependency names on PyPI (to prevent typo squatting)
2. **Use pip `--index-url`** (instead of `--extra-index-url`) or make the custom index the default via `pip.conf`
3. **Dependency pinning** — specify exact versions (`==x.y.z`)
4. **Package integrity verification** — check hashes (`--require-hashes`)
5. **SBOM (Software Bill of Materials)** — track all dependencies

## Vibe Coding Connection: How this error can be reproduced in AI code generation
When you ask AI to "create a PyTorch project for me", AI generates a `requirements.txt` or `pyproject.toml`. If AI does not specify package versions (like `torchtriton>=x.y.z`), you become vulnerable to dependency confusion attacks. When having AI generate a dependency list, ask it to specify exact versions for all packages and install using `--require-hashes`.

## 🔗 Source / Reference (URL)
- https://pytorch.org/blog/compromised-nightly-dependency/
- https://www.aquasec.com/blog/pytorch-dependency-confusion-administered-malware/
- https://www.reversinglabs.com/blog/pytorch-supply-chain-attack-dependency-confusion-burns-devops
