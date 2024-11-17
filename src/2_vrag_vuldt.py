'''
vrag enhancing vuln detection by providing vulnerabilities code snippets similar to target code in prompts
'''
import os
import json 
import jsonlines
from tqdm import tqdm
import utils as metrics_lib
from utils import MetricsMapping as mm
from prompts import format_dataset, task_templates
import torch
from llm2vec import LLM2Vec
from vrag_engine import VRAG_Engine


if __name__ == '__main__':
    pass
