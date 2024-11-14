import os
import json 
from tqdm import tqdm
from abc import ABC, abstractmethod
from typing import Optional, Union, List
import utils as metrics_lib
from utils import MetricsMapping as mm
from prompts import format_dataset, task_templates


'''
class VRAG_Engine
    Input: target function source code
    Output: vulnerability detection results in the history database
    Process: 1.embed the target function source code into the vector
             2.use annoy to find the most similar function in the history database
             3.return top k most similar functions
    methods: _load_emb_model, _load_annoy_index, _embedding_code, _find_similar_functions, run
'''
class VRAG_Engine:
    def __init__(
        self,
        emb_model: Agent,
        annoy_idx: Ann, 
        save_path: Optional[str] = None,
        result_name: Optional[str] = 'history_vulns.json'
    ):
        self.emb_model = emb_model
        self.annoy_idx = annoy_idx
        self.save_path = save_path
        self.result_name = result_name

    def _load_emb_model(self, path_to_model):
        """

        """
        pass

    def _load_annoy_index(self, path_to_ann):
        """

        """
        pass

    def _embedding_code(self, source_code):
        """

        """
        pass

    def _find_similar_functions(self, code_emb, top_k=5):
        """

        """
        pass
    
    def run(self):
        '''
        
        '''
        pass
