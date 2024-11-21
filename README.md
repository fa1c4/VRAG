# VRAG
Prototype of VRAG (Vulnerability Retrival-Augmented Generation) framwork for LLM detecting vulnerabilities in multi-languages source code.

Environmental Dependence
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

to do: create specific prompt pattern to utilze existed CVE vulnerabilities to enhance exclusive vulnearbilities detection
