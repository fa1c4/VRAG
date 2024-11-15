import os
import json 
from tqdm import tqdm
from abc import ABC, abstractmethod
from typing import Optional, Union, List
import utils as metrics_lib
from utils import MetricsMapping as mm
from prompts import format_dataset, task_templates
from annoy import AnnoyIndex
import torch
from llm2vec import LLM2Vec


'''
class VRAG_Engine
    Input: target function source code
    Output: vulnerability detection results in the history database
    Process: 1.embed the target function source code into the vector
             2.use annoy to find the most similar function in the history database
             3.return top k most similar functions
    methods: _load_emb_model, _load_annoy_index, _embedding_code, _find_similar_functions, run
'''
class Agent(ABC):
    def __init__(self):
        pass

    @abstractmethod
    def __call__(self, prompt):
        """
        input:
        {
            "system": str,
            "user": str
        }
        return: answer to the query (str)
        """
        pass


class VRAG_Engine:
    def __init__(
        self,
        emb_model: Agent,
        path_to_vulns_db: Optional[str] = '../data/vulns_db.json',
        path_to_annoy_index_tree: Optional[str] = '../data/annoy_index.ann', 
        save_path: Optional[str] = '../data/match',
        result_name: Optional[str] = 'similar_vulns.json'
    ):
        self.emb_model = emb_model
        self.path_to_vulns_db = path_to_vulns_db
        self.path_to_annoy_index_tree = path_to_annoy_index_tree
        self.save_path = save_path
        self.result_name = result_name
        self.vulns_db = None
        self.annoy_idx = None

        # load the database
        self._load_vulns_database()
        self._load_annoy_index()

    def _load_emb_model(self, path_to_model):
        """
        load the embedding model from the given path
        no need for this implementation, the model is transfered from the main function
        """
        pass

    def _load_annoy_index(self, vec_length=4096):
        """
        load the annoy index from the given path
        """
        # load index tree and calculate the similarity 
        ann_index = AnnoyIndex(vec_length, metric='angular')
        ann_index.load(self.path_to_annoy_index_tree)
        print('Annoy index tree loaded from:', self.path_to_annoy_index_tree)
        self.annoy_idx = ann_index

    def _embedding_code(self, source_code):
        """
        embed the source code into a vector
        """
        source_code_reps = self.emb_model.encode(source_code)
        source_code_reps_norm = torch.nn.functional.normalize(source_code_reps)
        self.code_emb = cve_function_reps_norm[0].tolist()

    def input_code_embedding(self, code_emb):
        """
        input the code embedding into the engine if the embeddings are already calculated
        """
        self.code_emb = code_emb

    def _find_similar_functions(self, code_emb, top_k):
        """
        fine the target code's most similar functions in the history database
        """
        assert self.annoy_idx is not None, 'Annoy index is not loaded'
        # get nearest k items, result is a list, elements in the list are integers of item indexes
        nearest_neighbors = self.annoy_idx.get_nns_by_vector(code_emb, top_k, include_distances=True)
        return nearest_neighbors # (neighbors, distances)
    
    def _load_vulns_database(self):
        """
        load the vulnerability database
        """
        # load the database using jsonlines
        with jsonlines.open(self.path_to_vulns_db) as reader:
            self.vulns_db = [obj for obj in reader]

    def _get_similar_vulns_info(self, nearest_neighbors):
        '''
        get the information of the similar vulnerabilities
        '''
        assert self.vulns_db is not None, 'Vulnerability database is not loaded'
        pass # to do here

    def query(self,
              source_code: Optional[str] = None, 
              code_emb: Optional[List[float]] = None,
              top_k=10):
        '''
        all pipeline runs here
        make sure the self.save_path exists
        '''
        assert source_code is None and code_emb is None, 'No input code provided'
        if source_code is not None:
            self._embedding_code(source_code)
        else:
            self.input_code_embedding(code_emb)

        # find the most similar functions
        nearest_neighbors = self._find_similar_functions(self.code_emb, top_k)
        query_results = self._get_similar_vulns_info(nearest_neighbors)
        return query_results
