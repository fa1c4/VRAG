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
---------------------------
to formatted dataset:
existence dataset:
{
    'code': xxx, # code_before
    'answer': xxx, # YES / NO
    'cwe': xxx, # cwe_id only number
    'idx': xxx # sequence number
}
{...}
...
---------------------------
type dataset:
{
    'selection': xxx,
    'code': xxx,
    'answer': xxx,
    'cwe': xxx,
    'idx': xxx,
}
{...}
...

target1: 50-50 real vulns and non-vulns
target2: 1000 real vulns to select 1 / 5 types of vulns

USAGE: python build_tasks_dataset.py
set the paths path_to_raw_dataset and path_to_formatted_datasets
'''
import re
import json
import jsonlines
import random
from tqdm import tqdm


# paths to dataset
path_to_raw_dataset = '../data/all_fixes_data_with_SHA256.json'
path_to_formatted_dataset_task1 = '../data/VulDetectBench/task1_code.jsonl'
path_to_formatted_dataset_task2 = '../data/VulDetectBench/task2_code.jsonl'

path_to_selections_task2 = '../data/VulDetectCWEs.json'

path_to_store_dataset_task1 = '../data/RealVulBench/task1_code.jsonl'
path_to_store_dataset_task2 = '../data/RealVulBench/task2_code.jsonl'

# set white list for CWEs 
CWE_whitelist_task1 = [
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

with jsonlines.open(path_to_formatted_dataset_task1, 'r') as reader:
    formatted_dataset_task1 = [obj for obj in reader]

with jsonlines.open(path_to_formatted_dataset_task2, 'r') as reader:
    formatted_dataset_task2 = [obj for obj in reader]

count_vulns = len(raw_dataset)
count_task1_vulns = len(formatted_dataset_task1)
count_task2_vulns = len(formatted_dataset_task2)

# inspecting dataset
'''
for key, _ in raw_dataset[0].items():
    print(f"'{key}': xxx,")

print('vulnerabilities count of dataset:', len(raw_dataset))

for key, _ in formatted_dataset_task1[0].items():
    print(f"'{key}': xxx,")

for key, _ in formatted_dataset_task2[0].items():
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

# get the selections of task2
selections_task2 = set()
for example in formatted_dataset_task2:
    for selection in example['selection'].split('\n'):
        # content = selection.split('.')[1]
        # use re to match A-Z. string and strip it then add to the set
        matched = re.search(r'[A-Z]\.', selection).group(0)
        if matched:
            # strip matched string in content
            content = selection.replace(matched, '')
            selections_task2.add(content)
        else:
            print(f'no matched: {selection}')
            continue

print('selections_task2:', len(selections_task2))
# for selection in selections_task2:
#     print(f"'{selection}'", end=',\n')

# write the selections sorted by dictionary order to the file
selections_task2_list = sorted(list(selections_task2))
with open(path_to_selections_task2, 'w') as f:
    json.dump(selections_task2_list, f, indent=4)

print(f'[+] selections of task2 stored to {path_to_selections_task2}')

'''
build the dataset for task1
'''
No_formatted_dataset_task1 = []
index = 0
for example in formatted_dataset_task1:
    index += 1
    if example['answer'] == 'NO':
        # formulating the index for the non-vuln
        example['idx'] = str(count_vulns + index)
        No_formatted_dataset_task1.append(example)

# print('vulnerabilities count of formatted dataset:', len(formatted_dataset_task1))
# print('vulnerabilities count of No formatted dataset:', len(No_formatted_dataset_task1))

dataset_to_store_task1 = [] + No_formatted_dataset_task1

# sample 500 vulnerabilities from raw_dataset
random.seed(42)
random.shuffle(raw_dataset)
for i, example in enumerate(tqdm(raw_dataset)):
    if random.random() > 0.05:
        continue
    
    if len(dataset_to_store_task1) >= 1000:
        break

    # filtering the dataset with CWE whitelist
    if example['cwe_id'] in CWE_whitelist_task1:
        dataset_to_store_task1.append({
            'code': example['code_before'],
            'answer': 'YES',
            'cwe': example['cwe_id'].lstrip('CWE-'),
            'idx': example['cid']
        })

assert len(dataset_to_store_task1) == 1000, f"dataset_to_store_task1 length is not 1000, length is {len(dataset_to_store_task1)}"

# store the dataset to the file
with jsonlines.open(path_to_store_dataset_task1, 'w') as writer:
    for example in dataset_to_store_task1:
        writer.write(example)

print('[+] dataset_to_store_task1 is stored to', path_to_store_dataset_task1)
print('length of dataset_to_store_task1:', len(dataset_to_store_task1))

'''
build the dataset for task2
'''
def get_CEW_in_white_list_task2(cwe_id, CWE_whitelist_task2):
    for cwe in CWE_whitelist_task2:
        if 'CWE' not in cwe:
            continue

        matched = re.search(r'CWE-\d+', cwe).group(0)
        if cwe_id == matched:
            return cwe
    return ''

# get correct answer content that starts with "A-Z."
def get_correct_answer_content(correct_selection, slct_content):
    for i, slct in enumerate(slct_content.split('\n')):
        if correct_selection in slct:
            return slct
    return ''

# read the selections_task2_list from the file
with open(path_to_selections_task2, 'r') as f:
    selections_task2_list = json.load(f)

print('selections_task2_list:', len(selections_task2_list))

# sample 1000 vulnerabilities from raw_dataset
random.seed(42)
random.shuffle(raw_dataset)
dataset_to_store_task2 = []
for i, example in enumerate(tqdm(raw_dataset)):
    if random.random() > 0.05:
        continue
    
    if len(dataset_to_store_task2) >= 1000:
        break

    # filtering the dataset with CWE whitelist
    correct_selection = get_CEW_in_white_list_task2(example['cwe_id'], selections_task2_list)
    if correct_selection != '':
        candidate_selections = [correct_selection]

        # sample 4 selections from selections_task2_list randomly
        while len(candidate_selections) < 5:
            slct_candidate = random.choice(selections_task2_list)
            if slct_candidate not in candidate_selections:
                candidate_selections.append(slct_candidate)

        # shuffle the candidate_selections
        random.shuffle(candidate_selections)
        slct_content = ''
        AZ = ['A', 'B', 'C', 'D', 'E', 'F']
        for j, slct in enumerate(candidate_selections):
            slct_content += f'{AZ[j]}.{slct}'
            if j < 4: slct_content += '\n'

        correct_answer_content = get_correct_answer_content(correct_selection, slct_content)
        assert correct_answer_content != '', f"correct_answer_content is empty, correct_selection: {correct_selection}, candidate_selections: {candidate_selections}"

        # store the dataset to the file
        dataset_to_store_task2.append({
            'selection': slct_content,
            'code': example['code_before'],
            'answer': correct_answer_content,
            'cwe': example['cwe_id'].lstrip('CWE-'),
            'idx': count_vulns + count_task1_vulns + i
        })

assert len(dataset_to_store_task2) == 1000, f"dataset_to_store_task2 length is not 1000, length is {len(dataset_to_store_task2)}"

# store the dataset to the file
with jsonlines.open(path_to_store_dataset_task2, 'w') as writer:
    for example in dataset_to_store_task2:
        writer.write(example)

print('[+] dataset_to_store_task2 is stored to', path_to_store_dataset_task2)
print('length of dataset_to_store_task2:', len(dataset_to_store_task2))
