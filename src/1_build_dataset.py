'''
code to build the dataset for VRAG
from the raw dataset:
{
    'cve_id': xxx,
    'hash': xxx,
    'filename': xxx,
    'old_path': xxx,
    'new_path': xxx,
    'change_type': xxx,
    'diff': xxx,
    'diff_parsed': xxx,
    'num_lines_added': xxx,
    'num_lines_deleted': xxx,
    'code_before': xxx,
    'code_after': xxx,
    'nloc': xxx,
    'token_count': xxx,
    'programming_language': xxx,
    'cwe_id': xxx,
    'repo_url': xxx,
    'description': xxx,
    'cid': xxx,
    'SHA256': xxx
}
{...}
...
to formatted dataset:
{
    'code': xxx, # code_before
    'answer': xxx, # YES / NO
    'cwe': xxx, # cwe_id only number
    'idx': xxx # sequence number
}
{...}
...

target: 50-50 real vulns and non-vulns

USAGE: python 1_build_dataset.py
set the paths path_to_raw_dataset and path_to_formatted_dataset
'''

import json
import jsonlines
import random
from tqdm import tqdm


# paths to dataset
path_to_raw_dataset = '../data/all_fixes_data_with_SHA256.json'
path_to_formatted_dataset = '../data/VulDetectBench/task1_code.jsonl'
path_to_store_dataset = '../data/RealVulBench/real_vul_dataset.jsonl'

# set white list for CWEs 
CWE_whitelist = [
    'CWE-369', 'CWE-828', 'CWE-821', 'CWE-663', 'CWE-74', 
    'CWE-125', 'CWE-59', 'CWE-415', 'CWE-833', 'CWE-170', 
    'CWE-834', 'CWE-476', 'CWE-839', 'CWE-806', 'CWE-401', 
    'CWE-36', 'CWE-195', 'CWE-805', 'CWE-363', 'CWE-835', 
    'CWE-134', 'CWE-126', 'CWE-774', 'CWE-414', 'CWE-785', 
    'CWE-0', 'CWE-78', 'CWE-775', 'CWE-824', 'CWE-789', 
    'CWE-764', 'CWE-191', 'CWE-771', 'CWE-15', 'CWE-197', 
    'CWE-190', 'CWE-119', 'CWE-820', 'CWE-590', 'CWE-127'
]

with jsonlines.open(path_to_raw_dataset, 'r') as reader:
    raw_dataset = [obj for obj in reader]

with jsonlines.open(path_to_formatted_dataset, 'r') as reader:
    formatted_dataset = [obj for obj in reader]

count_vulns = len(raw_dataset)

# inspecting dataset
'''
for key, _ in raw_dataset[0].items():
    print(f"'{key}': xxx,")

print('vulnerabilities count of dataset:', len(raw_dataset))

for key, _ in formatted_dataset[0].items():
    print(f"'{key}': xxx,")

raw_CWEs, formatted_CWEs = set(), set()
for example in raw_dataset:
    raw_CWEs.add(example['cwe_id'])

for example in formatted_dataset:
    formatted_CWEs.add(example['cwe'])

print('raw dataset CWEs:', raw_CWEs)
print('formatted dataset CWEs:', formatted_CWEs)
normalized_CWEs = set()
for cwe in formatted_CWEs:
    # print(f"'CWE-{cwe}'", end=', ')
    normalized_CWEs.add(f'CWE-{cwe}')

# get intersection of CWEs
intersection = raw_CWEs.intersection(normalized_CWEs)
print('length of intersection of CWEs', len(intersection))
'''

No_formatted_dataset = []
index = 0
for example in formatted_dataset:
    index += 1
    if example['answer'] == 'NO':
        # formulating the index for the non-vuln
        example['idx'] = str(count_vulns + index)
        No_formatted_dataset.append(example)

# print('vulnerabilities count of formatted dataset:', len(formatted_dataset))
# print('vulnerabilities count of No formatted dataset:', len(No_formatted_dataset))

dataset_to_store = [] + No_formatted_dataset

# sample 500 vulnerabilities from raw_dataset
random.seed(42)
random.shuffle(raw_dataset)
for i, example in enumerate(tqdm(raw_dataset)):
    if random.random() > 0.99:
        continue
    
    if len(dataset_to_store) >= 1000:
        break

    # filtering the dataset with CWE whitelist
    if example['cwe_id'] in CWE_whitelist:
        dataset_to_store.append({
            'code': example['code_before'],
            'answer': 'YES',
            'cwe': example['cwe_id'].lstrip('CWE-'),
            'idx': example['cid']
        })

assert len(dataset_to_store) == 1000, f"dataset_to_store length is not 1000, length is {len(dataset_to_store)}"

# store the dataset to the file
with jsonlines.open(path_to_store_dataset, 'w') as writer:
    for example in dataset_to_store:
        writer.write(example)

print('[+] dataset_to_store is stored to', path_to_store_dataset)
print('length of dataset_to_store:', len(dataset_to_store))
