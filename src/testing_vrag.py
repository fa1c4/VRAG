'''
testing the vrag functionality, loading the model and testing the query function
CUDA_VISIBLE_DEVICES=0 python lab_vrag_testing.py

insight: different models has different parameters with same understanding of the code
'''
import torch
import jsonlines
from llm2vec import LLM2Vec
from vrag_engine import VRAG_Engine


path_to_all_fixes_data = '../data/all_fixes_data_with_SHA256.json'
path_to_base_model = '../../Models/LLM2Vec-Meta-Llama-3-8B-Instruct-mntp'


# need to sheild the code with __name__ == "__main__" to avoid the multiprocess error
if __name__ == "__main__":
    # load embedding model
    l2v = LLM2Vec.from_pretrained(
        path_to_base_model,
        # peft_model_name_or_path=path_to_peft_model,
        device_map="cuda" if torch.cuda.is_available() else "cpu",
        torch_dtype=torch.bfloat16,
        local_files_only=True
    )

    # load the VRAG engine
    vrag_engine = VRAG_Engine(emb_model=l2v)

    # load all the data
    with jsonlines.open(path_to_all_fixes_data) as reader:
        vulns_db = [obj for obj in reader]
    print('Vulnerability data loaded')

    # test the VRAG
    source_code = vulns_db[0]['code_before']
    target_cwe = vulns_db[0]['cwe_id']
    target_desc = vulns_db[0]['description']
    print('testing source code', source_code)
    results = vrag_engine.query(source_code=source_code, result_name='test1.json')
    # print(results)
    print(target_cwe, target_desc)

    source_code = vulns_db[100]['code_before']
    target_cwe = vulns_db[100]['cwe_id']
    target_desc = vulns_db[100]['description']
    print('testing source code', source_code)
    results = vrag_engine.query(source_code=source_code, result_name='test100.json')
    # print(results)
    print(target_cwe, target_desc)

    source_code = vulns_db[10000]['code_before']
    target_cwe = vulns_db[10000]['cwe_id']
    target_desc = vulns_db[10000]['description']
    print('testing source code', source_code)
    results = vrag_engine.query(source_code=source_code, result_name='test10000.json')
    # print(results)
    print(target_cwe, target_desc)
    print(results['CVE'])
    print(results['CWE'])
