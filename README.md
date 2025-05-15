# VRAG
Prototype of VRAG (Vulnerability Retrival-Augmented Generation) framwork for LLM detecting vulnerabilities in multi-languages source code.

## Environmental Dependence
```shell
# requiring python>=3.10
conda create -n VRAG python=3.10

# install llm2vec for code embedding
cd ~
git clone git@github.com:McGill-NLP/llm2vec.git
cd llm2vec
pip install -e .
pip install flash-attn --no-build-isolation
```

## Evaluation
before build dataset, put the vulnerabilities dataset into data directory.
the format of raw dataset refer to `build_*_dataset.py` comments
```shell
conda activate VRAG
cd src
python build_tasks_dataset.py
python build_classes_dataset.py

# export the OPENAI_KEY as environment variable
python vrag_engine.py

# the results will be saved at results/
```

## TODO
(1) create specific prompt pattern to utilze existed CVE vulnerabilities to enhance exclusive vulnearbilities detection
(2) reproduce existed CoT template as one enhancement 
