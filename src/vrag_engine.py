import os
import json 
import jsonlines
from tqdm import tqdm
from abc import ABC, abstractmethod
from typing import Optional, Union, List
import utils as metrics_lib
from utils import MetricsMapping as mm
from prompts import format_dataset, task_templates
from annoy import AnnoyIndex
import torch


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


'''
Input: embedding model
Output: 
    query_results: {
        "CVE": List[str],
        "CWE": List[str],
        "distance": List[float],
        "description": List[str],
        "code": List[str]
    }
'''
class VRAG_Engine:
    def __init__(
        self,
        emb_model: Agent,
        path_to_vulns_db: Optional[str] = '../data/all_fixes_data_with_SHA256.json',
        path_to_annoy_index_tree: Optional[str] = '../data/annoy_index_tree.ann', 
        save_path: Optional[str] = '../data/matched',
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
        source_code_reps = self.emb_model.encode(source_code, show_progress_bar=False)
        source_code_reps_norm = torch.nn.functional.normalize(source_code_reps)
        self.code_emb = source_code_reps_norm[0].tolist()

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
        query_results = {}
        CVE_results, CWE_results, dist_results, desc_results, code_results = [], [], [], [], []
        for idx, dist in zip(nearest_neighbors[0], nearest_neighbors[1]):
            vuln = self.vulns_db[idx]
            CVE_results.append(vuln['cve_id'])
            CWE_results.append(vuln['cwe_id'])
            dist_results.append(dist)
            desc_results.append(vuln['description'])
            code_results.append(vuln['code_before'])

        query_results['CVE'] = CVE_results
        query_results['CWE'] = CWE_results
        query_results['distance'] = dist_results
        query_results['description'] = desc_results
        query_results['code'] = code_results
        return query_results

    def query(self,
              source_code: Optional[str] = None, 
              code_emb: Optional[List[float]] = None,
              top_k=10,
              result_name: Optional[str] = None):
        '''
        all pipeline runs here
        make sure the self.save_path exists
        '''
        assert source_code is not None or code_emb is not None, 'No input code provided'
        if source_code is not None:
            # llm2vec model takes a list of source code as input
            source_code_list = [source_code]
            self._embedding_code(source_code_list)
        else:
            self.input_code_embedding(code_emb)

        # find the most similar functions
        nearest_neighbors = self._find_similar_functions(self.code_emb, top_k)
        query_results = self._get_similar_vulns_info(nearest_neighbors)

        # save the results
        if result_name is not None:
            self.result_name = result_name

        if not os.path.exists(self.save_path):
            os.makedirs(self.save_path)
            
        path_to_save_results = os.path.join(self.save_path, self.result_name)
        save_content = {}
        if source_code is not None:
            save_content['query_code'] = source_code
        else:
            save_content['query_code'] = 'code embedding'
            save_content['code_emb'] = self.code_emb
        
        save_content['top_k'] = top_k
        query_res_saved = []
        for i in range(top_k):
            query_res_tmp = {}
            query_res_tmp['CVE'] = query_results['CVE'][i]
            query_res_tmp['CWE'] = query_results['CWE'][i]
            query_res_tmp['distance'] = query_results['distance'][i]
            query_res_tmp['description'] = query_results['description'][i]
            query_res_tmp['code'] = query_results['code'][i]
            query_res_saved.append(query_res_tmp)

        save_content['query_results'] = query_res_saved
        with open(path_to_save_results, 'w') as f:
            json.dump(save_content, f, indent=4)
        print('Results saved to:', path_to_save_results)

        return query_results


'''
vuldetectbench dataset format:
{
    "code": str,
    "answer": "NO" | "YES",
    "cwe": str,
    "idx": str    
}
adding examples to dataset format:
{
    "code": str,
    "answer": "NO" | "YES",
    "cwe": str,
    "example": str,
    "idx": str    
}
'''
def adding_examples_to_dataset(emb_model, raw_dataset, threshold=0.3):
    processed_dataset = []
    # load the VRAG engine
    VRAG_inst = VRAG_Engine(emb_model)

    for raw_sample in tqdm(raw_dataset):
        source_code = raw_sample['code']
        results = VRAG_inst.query(source_code=source_code)
        # check the similarity score, if it is less than the threshold, add the example
        example = 'Here is a relative vulnerability example in database:\n'
        if results['distance'][0] <= threshold:
            example += results['code'][0]
            # add the vulnerability description to example
            example += '\n' + results['description'][0]
        else: # if no similar vulnerabilities found, then example is empty
            example = ''
        
        tmp_sample = {}
        tmp_sample['code'] = raw_sample['code']
        tmp_sample['answer'] = raw_sample['answer']
        tmp_sample['cwe'] = raw_sample['cwe']
        tmp_sample['example'] = example
        tmp_sample['idx'] = raw_sample['idx']
        processed_dataset.append(tmp_sample)
    
    return processed_dataset
