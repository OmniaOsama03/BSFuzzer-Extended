# BSFuzz
## Project Overview
BSFuzzer is a context-aware semantic fuzzing framework guided by the Bluetooth Core Specification. It addresses the critical gap in detecting logic vulnerabilities in BLE protocol implementations by leveraging Large Language Model (LLM) agents for intelligent test generation and verification.

## Requirements
- Python 3.11
- Ubuntu 22.04.4 LTS
- [Conda](https://docs.conda.io/en/latest/miniconda.html)

## Installation

### 1. Create a virtual environment

```
conda create -n BSFuzz_env python=3.11.8
conda activate BSFuzz_env
pip install -r requirements.txt
conda deactivate
```

### 2. Clone the repository
```
git clone https://github.com/yangting111/BSFuzz.git
cd BSFuzz
```
