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

```

### 2. Clone the repository
```
git clone https://github.com/yangting111/BSFuzz.git
cd BSFuzz
pip install -r requirements.txt
```

## Project Structure

```
BSFuzz/
├── srcs/                          # Source code directory
│   ├── Bug_Verification/          # Bug verification and validation modules
│   │   ├── Validation.py          # Validation logic for field and state rules
│   │   ├── Field-Level_Rule_Extraction.py
│   │   └── State-Level_Rule_Extraction.py
│   ├── Test_Seq_Generation/       # Test sequence generation
│   │   ├── SemFuzz.py            # Main fuzzing framework
│   │   ├── Field_Seed.py         # Field-level seed generation
│   │   ├── State_Seed.py         # State-level seed generation
│   │   ├── Field_Seed_Parse.py   # Field seed parsing
│   │   └── State_Seed_Parse.py   # State seed parsing
│   ├── Semantic_Parsing/          # Semantic parsing modules
│   │   ├── Packet_Packet_Semantics.py
│   │   ├── Single_Field_Semantics.py
│   │   ├── PDF_txt.py            # PDF to text conversion
│   │   └── Txt_faiss.py          # FAISS vector database creation
│   ├── Send_Packet/               # Packet construction and sending
│   │   ├── Bluetooth_SUL.py      # Bluetooth System Under Test interface
│   │   ├── Packet_Constuction.py # Packet construction logic
│   │   ├── BLE_ADV.py            # Advertisement packet handling
│   │   ├── BLE_LL.py             # Link Layer packet handling
│   │   ├── BLE_L2CAP.py          # L2CAP packet handling
│   │   ├── BLE_ATT.py            # ATT packet handling
│   │   └── BLE_SMP.py            # SMP packet handling
│   ├── Config_File/               # Configuration files
│   ├── llm_model/                 # LLM model integration
│   ├── prompt/                    # Prompt templates for LLM
│   └── Log_Config/                # Logging configuration
├── config/                        # Configuration files
│   ├── semfuzz_config.json       # Main fuzzing configuration
│   ├── semseed_config.json       # Seed generation configuration
│   └── semresult_config.json     # Result processing configuration
├── data/                          # Data directory
│   ├── sem_seed/                  # Semantic seeds
│   ├── vector_db/                 # FAISS vector databases
│   └── Message_Chart/             # Message sequence charts
├── result/                        # Output results
│   └── log_file/                  # Log files
├── libs/                          # External libraries
├── requirements.txt               # Python dependencies
└── Readme.md                      # This file
```

## Usage

### Step 1: Semantic Extraction and Vector Database Construction

This step extracts semantic information from Bluetooth Core Specification PDFs and builds vector databases for LLM retrieval.

#### 1.1 Convert PDF to Text
```bash
python srcs/Semantic_Parsing/PDF_txt.py
```
This converts Bluetooth specification PDFs (SMP, L2CAP, ATT, LL) to text files stored in `data/V5.0/`.

#### 1.2 Build FAISS Vector Database
```bash
python srcs/Semantic_Parsing/Txt_faiss.py
```
This creates FAISS vector databases for semantic retrieval, stored in `data/vector_db/`.

#### 1.3 Convert Message Sequence Charts to DOT Format
```bash
python srcs/Semantic_Parsing/MSC_dot.py --model_provider grok
```
This converts Message Sequence Chart (MSC) Markdown files to DOT format (Graphviz format) using LLM. The converted files are stored in `result/state_construction/`.

**Options:**
- `--model_provider`: LLM provider (default: google, options: openai, grok, deepseek, hw, nivida, ali, google, Zeta)
- `--limit N`: Process only the first N files (0 for all)
- `--dry`: Preview prompts without calling the model
- `--out PATH`: Output directory (default: `result/state_construction`)

#### 1.4 Extract Field Semantics
```bash
python srcs/Semantic_Parsing/Single_Field_Semantics.py
```
This extracts semantic information for individual fields and generates XML files.

#### 1.5 Extract Packet Dependencies
```bash
python srcs/Semantic_Parsing/Packet_Packet_Semantics.py
```
This analyzes and extracts dependencies between packets, generating `data/sem_seed/pkt_dependency.json`.

#### 1.6 Merge XML Files (Optional)
```bash
python srcs/Semantic_Parsing/merge.py
```
This merges XML files from different layers into a unified `merged.xml` file.

### Step 2: Test Seed Generation

This step generates test seeds using LLM agents based on the extracted semantics.

#### 2.1 Generate Field-Level Seeds
```bash
python srcs/Test_Seq_Generation/Field_Seed.py
```
This generates field-level mutation seeds, output to `data/sem_seed/${model_provider}/field_semseed.json`.

#### 2.2 Generate State-Level Seeds
```bash
python srcs/Test_Seq_Generation/State_Seed.py
```
This generates state-level mutation seeds, output to `data/sem_seed/${model_provider}/state_seed.json`.

#### 2.3 Parse Field Seeds
```bash
python srcs/Test_Seq_Generation/Field_Seed_Parse.py
```
This parses field seeds and generates structured seed files.

#### 2.4 Parse State Seeds
```bash
python srcs/Test_Seq_Generation/State_Seed_Parse.py
```
This parses state seeds and generates structured seed files.

#### 2.5 Deduplicate Field Seeds (Optional)
```bash
python srcs/Test_Seq_Generation/Field_Seed_deduplicate.py
```
This removes duplicate field seeds from the seed file.

### Step 3: Fuzzing Execution

This step executes the semantic fuzzing framework against the target BLE device.

```bash
python srcs/ble_fuzzing.py
```
This runs the main fuzzing framework. Make sure to configure:
- Target device settings in `srcs/Config_File/`
- Fuzzing parameters in `config/semfuzz_config.json`
- Seed file paths in the configuration

The fuzzing results are stored in `result/log_file/`.

### Step 4: Bug Verification

This step validates detected anomalies using specification-based rules.

#### 4.1 Extract Field-Level Validation Rules
```bash
python srcs/Bug_Verification/Field-Level_Rule_Extraction.py
```
This extracts validation rules for field-level mutations from the specification.

#### 4.2 Extract State-Level Validation Rules
```bash
python srcs/Bug_Verification/State-Level_Rule_Extraction.py
```
This extracts validation rules for state-level mutations from the specification.

#### 4.3 Validate Results
```bash
python srcs/Bug_Verification/Validation.py
```
This validates fuzzing results against the extracted rules and generates validation reports.

### Configuration

Before running, ensure the following configuration files are properly set:

- **`config/semext_config.json`**: Semantic extraction configuration (PDF paths, vector DB paths)
- **`config/semseed_config.json`**: Seed generation configuration (LLM settings, output paths)
- **`config/semfuzz_config.json`**: Fuzzing configuration (seed file paths, XML paths)
- **`config/semresult_config.json`**: Result processing configuration (validation rule paths)

### Important Notes

1. **Order of Execution**: Follow the steps sequentially as each step depends on outputs from previous steps.
2. **LLM Configuration**: Ensure your LLM API keys are configured in the model configuration files.
3. **Target Device**: Configure the target BLE device settings before running fuzzing.
4. **Resource Requirements**: Vector database construction and seed generation may take significant time depending on the dataset size.
