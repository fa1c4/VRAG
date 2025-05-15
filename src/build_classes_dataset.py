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

target1: all real vulns among n CWE types, total samples n * 100
target2: n * 100 real vulns to select 1 / 5 types of vulns

USAGE: python build_classes_dataset.py
set the paths path_to_raw_dataset and path_to_formatted_datasets
'''
import re
import json
import jsonlines
import random
from tqdm import tqdm


# paths to dataset
path_to_raw_dataset = '../data/all_fixes_data_with_SHA256.json'
path_to_store_dataset_task1 = '../data/CWEClassesBench/task1_code.jsonl'
path_to_store_dataset_task2 = '../data/CWEClassesBench/task2_code.jsonl'

# set white list for CWEs 
cwe_dict = {
    "CWE-20": {
        "title": "Improper Input Validation",
        "description": "Occurs when software does not validate or improperly validates input, affecting a program's control or data flow. This can lead to unauthorized access, denial of service, or privilege escalation."
    },
    "CWE-78": {
        "title": "OS Command Injection",
        "description": "An application allows the execution of arbitrary OS commands due to inadequate input validation, which can result in a complete system takeover."
    },
    "CWE-119": {
        "title": "Improper Restriction of Operations within the Bounds of a Memory Buffer",
        "description": "A buffer overflow occurs when a program operates on more data than the size of its memory buffer. It can allow arbitrary code execution, control flow alteration, or system crash."
    },
    "CWE-120": {
        "title": "Buffer Copy without Checking Size of Input (Classic Buffer Overflow)",
        "description": "A specific instance of buffer overflow caused by buffer copy operations without adequate size checks of the input."
    },
    "CWE-121": {
        "title": "Stack-based Buffer Overflow",
        "description": "Occurs in stack memory, potentially leading to arbitrary code execution or manipulation of program execution flow by overwriting critical data."
    },
    "CWE-122": {
        "title": "Heap-based Buffer Overflow",
        "description": "Similar to stack-based but occurs in heap memory, leading to data corruption or unexpected behavior through manipulated pointers."
    },
    "CWE-190": {
        "title": "Integer Overflow or Wraparound",
        "description": "Happens when an integer operation produces a value too large to be held by the integer type, causing the value to wrap and create unintended values, leading to errors or vulnerabilities."
    },
    "CWE-476": {
        "title": "NULL Pointer Dereference",
        "description": "It occurs when a program dereferences a pointer, which it expects to be valid but is NULL, leading to crashes or code execution."
    },
    "CWE-762": {
        "title": "Mismatched Memory Management Routines",
        "description": "Arises when memory is allocated and deallocated with different routines, potentially leading to heap corruption or crashes."
    },
    "CWE-787": {
        "title": "Out-of-bounds Write",
        "description": "It happens when software writes data outside the intended buffer boundaries, leading to data corruption, crashes, or code execution vulnerabilities."
    }
}

CWE_whitelist = list(cwe_dict.keys())
CWEs_count = len(CWE_whitelist)

with jsonlines.open(path_to_raw_dataset, 'r') as reader:
    raw_dataset = [obj for obj in reader]

count_vulns = len(raw_dataset)

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

'''
build the dataset for task1
'''
dataset_to_store_task1 = []
CWEs_statistics = {}
for cwe in CWE_whitelist:
    CWEs_statistics[cwe] = 0

# sample n * 100 vulnerabilities from raw_dataset
random.seed(42)
random.shuffle(raw_dataset)
for i, example in enumerate(tqdm(raw_dataset)):    
    # if len(dataset_to_store_task1) >= 100 * CWEs_count:
    #     break

    # filter none code
    if example['code_before'] == '' or example['code_before'] == 'None':
        continue

    # filtering the dataset with CWE whitelist
    if example['cwe_id'] in CWE_whitelist:
        dataset_to_store_task1.append({
            'code': example['code_before'],
            'answer': 'YES',
            'cwe': example['cwe_id'].lstrip('CWE-'),
            'idx': example['cid']
        })
        CWEs_statistics[example['cwe_id']] += 1

# print the statistics of CWEs
print('CWEs statistics:')
for cwe, count in CWEs_statistics.items():
    print(f'{cwe}: {count}')

# for each CWE, sample 100 vulnerabilities
filtered_dataset_to_store_task1 = []
for cwe in CWE_whitelist:
    count = 0
    for example in dataset_to_store_task1:
        if 'CWE-' + example['cwe'] == cwe:
            filtered_dataset_to_store_task1.append(example)
            count += 1
            if count >= 100:
                break

# store the dataset to the file
with jsonlines.open(path_to_store_dataset_task1, 'w') as writer:
    for example in filtered_dataset_to_store_task1:
        writer.write(example)

print('[+] dataset_to_store_task1 is stored to', path_to_store_dataset_task1)
print('length of dataset_to_store_task1:', len(filtered_dataset_to_store_task1))


'''
build the dataset for task2
'''
def get_CEW_in_white_list_task2(cwe_id):
    for cwe in CWE_whitelist:
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

# sample n * 100 vulnerabilities from raw_dataset
count_task1_vulns = len(dataset_to_store_task1)

random.seed(42)
random.shuffle(raw_dataset)
dataset_to_store_task2 = []
for i, example in enumerate(tqdm(raw_dataset)):    
    # if len(dataset_to_store_task2) >= 100 * CWEs_count:
    #     break

    # filtering the dataset with CWE whitelist
    correct_selection = get_CEW_in_white_list_task2(example['cwe_id'])
    if correct_selection != '':
        candidate_selections = [correct_selection]

        # sample 4 selections from selections_task2_list randomly
        while len(candidate_selections) < 5:
            slct_candidate = random.choice(CWE_whitelist)
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

        # filter none code
        if example['code_before'] == '' or example['code_before'] == 'None':
            continue

        # store the dataset to the file
        dataset_to_store_task2.append({
            'selection': slct_content,
            'code': example['code_before'],
            'answer': correct_answer_content,
            'cwe': example['cwe_id'].lstrip('CWE-'),
            'idx': count_vulns + count_task1_vulns + i
        })

# for each CWE, sample 100 vulnerabilities
filtered_dataset_to_store_task2 = []
for cwe in CWE_whitelist:
    count = 0
    for example in dataset_to_store_task2:
        if 'CWE-' + example['cwe'] == cwe:
            filtered_dataset_to_store_task2.append(example)
            count += 1
            if count >= 100:
                break

# store the dataset to the file
with jsonlines.open(path_to_store_dataset_task2, 'w') as writer:
    for example in filtered_dataset_to_store_task2:
        writer.write(example)

print('[+] dataset_to_store_task2 is stored to', path_to_store_dataset_task2)
print('length of dataset_to_store_task2:', len(filtered_dataset_to_store_task2))
