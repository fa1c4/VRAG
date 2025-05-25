'''
script code to calculate metrics for task1 and task2 divided by CWE
input data format
task1_results:
[
  {
    "overall metrics": [
      {
        "Accuracy": 0.3
      },
      {
        "F1-Score": 0.4
      }
    ],
    "verbose": [
      {
        "id": 51995,
        "gold": "YES",
        "metrics": [
          {
            "single metric": "hit",
            "extracted answer": "YES",
            "score": 1,
            "prompt": {
              "system": "xxx",
              "user": "xxx",
              "example": ""
            },
            "original answer": "YES"
          }
        ]
      },
      {...},
      ...
    ]
  }
]

task2_results:
[
  {
    "overall metrics": [
      {
        "Avg Moderate Evaluation Score": 0.2
      },
      {
        "Avg Strict Evaluation Score": 0.2
      }
    ],
    "verbose": [
      {
        "id": 177323,
        "gold": "D.CWE-20",
        "metrics": [
          {
            "single metric": "Moderate Evaluation Score",
            "extracted answer": "",
            "score": 0,
            "prompt": {
              "system": "xxx",
              "user": "xxx",
              "example": ""
            },
            "original answer": "A."
          },
          {
            "single metric": "Strict Evaluation Score",
            "extracted answer": "",
            "score": 0,
            "prompt": {
              "system": "xxx",
              "user": "xxx",
              "example": ""
            },
            "original answer": "A."
          }
        ]
      },
      {...},
      ...
    ]
  }
] 

task_bench:
{"code": "xxx", "answer": "YES", "cwe": "20", "idx": 51995}
{...}
...
'''
import re
import json
import jsonlines
from sklearn.metrics import (
    accuracy_score, 
    precision_score, 
    recall_score, 
    f1_score, 
    classification_report
)


def calculate_binary_metrics(y_true, y_pred):
    accuracy = accuracy_score(y_true, y_pred)
    precision = precision_score(y_true, y_pred, average='macro', zero_division=0)
    recall = recall_score(y_true, y_pred, average='macro', zero_division=0)
    f1 = f1_score(y_true, y_pred, average='macro', zero_division=0)
    report = classification_report(y_true, y_pred, zero_division=0)
    return {
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "report": report
    }


def calculate_multiclasses_metrics(y_true, y_pred):
    accuracy = accuracy_score(y_true, y_pred)
    precision = precision_score(y_true, y_pred, average='macro', zero_division=0)
    recall = recall_score(y_true, y_pred, average='macro', zero_division=0)
    f1 = f1_score(y_true, y_pred, average='macro', zero_division=0)
    report = classification_report(y_true, y_pred, zero_division=0)
    return {
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "report": report
    }


# get cwe number from string by re search
def get_cwe_number(cwe_string):
    match = re.search(r'CWE-\d+', cwe_string)
    if match:
        return match.group(0).replace('CWE-', '')
    else:
        raise ValueError(f"Invalid CWE string: {cwe_string}")


def get_CWE_by_id(task_bench, res_id):
    for example in task_bench:
        if example['idx'] == res_id:
            return example['cwe']
    raise ValueError(f"CWE not found for id: {res_id}")


def filter_results_by_cwe(task_bench, task_results, cwe):
    filtered = []
    for result in task_results:
        res_id = result['id']
        cwe_ground = get_CWE_by_id(task_bench, res_id)
        if cwe_ground == cwe:
            filtered.append(result)
    return filtered


def get_bench_by_id(task_bench, res_id):
    for example in task_bench:
        if example['idx'] == res_id:
            return example
    raise ValueError(f"Task benchmark not found for id: {res_id}")


def get_pred_cwe_number(task_bench, res_id, pred):
    task_bench_id = get_bench_by_id(task_bench, res_id)
    slct_list = task_bench_id['selection'].split('\n')
    assert len(slct_list) == 5, f"[-] id-{res_id}: selection list length is not 5"
    for slct in slct_list:
        if slct.startswith(pred + '.'):
            cwe_num = get_cwe_number(slct)
            return cwe_num
    raise ValueError(f"[-] id-{res_id}: pred not in selection list")


def get_task1_y_true_and_y_pred(task1_results):
    y_true, y_pred = [], []
    for result in task1_results:
        if len(result['metrics'][0]['original answer']) == 0:
            continue

        gold = result['gold']
        assert len(result['metrics']) == 1
        pred = result['metrics'][0]['extracted answer']
        # allow pred is substring of original answer
        assert pred == result['metrics'][0]['original answer'] or pred in result['metrics'][0]['original answer'], \
            f"[-] id-{result['id']}: pred and original answer mismatch"
        y_true.append(gold)
        y_pred.append(pred)
    return y_true, y_pred


def get_task2_y_true_and_y_pred(task2_bench, task2_results):
    y_true, y_pred = [], []
    for result in task2_results:
        check_tmp = result['metrics'][0]['original answer']
        if len(check_tmp) == 0 or len(check_tmp) > 2:
            continue
        if not check_tmp[0] in ['A', 'B', 'C', 'D', 'E']:
            continue

        gold = get_cwe_number(result['gold'])
        assert len(result['metrics']) == 2

        pred = get_pred_cwe_number(task2_bench, result['id'], check_tmp.split('.')[0])
        assert pred in ['20', '78', '119', '120', '121', '122', '190', '476', '762', '787'], \
            f"[-] id-{result['id']}: pred not in allowed classes"
        
        y_true.append(gold)
        y_pred.append(pred)

    return y_true, y_pred


def cal_all_cwes_metrics(task1_bench, task1_results, task2_bench, task2_results, CWE_list, path_to_save):
    all_metrics = []
    for cwe_id in CWE_list:
        cwe_num = cwe_id.replace('CWE-', '')

        # task1
        filtered_task1_results = filter_results_by_cwe(task1_bench, task1_results, cwe_num)
        if filtered_task1_results:
            y_true_t1, y_pred_t1 = get_task1_y_true_and_y_pred(filtered_task1_results)

        if len(y_true_t1) > 0 and len(y_pred_t1) > 0:
            metrics_t1 = calculate_binary_metrics(y_true_t1, y_pred_t1)
        else:
            metrics_t1 = None

        # task2
        filtered_task2_results = filter_results_by_cwe(task2_bench, task2_results, cwe_num)
        if filtered_task2_results:
            y_true_t2, y_pred_t2 = get_task2_y_true_and_y_pred(task2_bench, filtered_task2_results)
            
        if len(y_true_t2) > 0 and len(y_pred_t2) > 0:
            metrics_t2 = calculate_multiclasses_metrics(y_true_t2, y_pred_t2)
        else:
            metrics_t2 = None

        print(f"[CWE-{cwe_num}] task1 samples: {len(filtered_task1_results)}, task2 samples: {len(filtered_task2_results)}")
        print(f"[CWE-{cwe_num}] task1 metrics: {metrics_t1}")
        print(f"[CWE-{cwe_num}] task2 metrics: {metrics_t2}")

        all_metrics.append({
            "CWE": cwe_id,
            "task1_metrics": metrics_t1,
            "task2_metrics": metrics_t2
        })

    # save all CWE metrics
    with open(path_to_save, 'w') as f:
        json.dump(all_metrics, f, indent=4)

    print(f"All CWE metrics saved to {path_to_save}")


# calculate total metrics for task1 and task2
def cal_total_metrics(task1_results, task2_bench, task2_results, path_to_save_total_res):
    y_true_t1, y_pred_t1 = get_task1_y_true_and_y_pred(task1_results)
    metrics_t1 = calculate_binary_metrics(y_true_t1, y_pred_t1)

    y_true_t2, y_pred_t2 = get_task2_y_true_and_y_pred(task2_bench, task2_results)
    metrics_t2 = calculate_multiclasses_metrics(y_true_t2, y_pred_t2)

    total_metrics = {
        "task1_metrics": metrics_t1,
        "task2_metrics": metrics_t2
    }

    with open(path_to_save_total_res, 'w') as f:
        json.dump(total_metrics, f, indent=4)
    print(f"Total metrics saved to {path_to_save_total_res}")


if __name__ == '__main__':
    model_name = 'deepseek-chat' # deepseek-chat, deepseek-coder, deepseek-reasoner
    method_name = 'zero-shot' # zero-shot, few-shot
    benchmark_name = 'CWEClassesBench'
    threshold_val = 0.1

    task1_results_path = f'../results/{model_name}_{benchmark_name}_{method_name}_threshold{threshold_val}_task1_eval.json'
    task2_results_path = f'../results/{model_name}_{benchmark_name}_{method_name}_threshold{threshold_val}_task2_eval.json'
    path_to_save_total_res = f'../results/{model_name}_{benchmark_name}_{method_name}_total_results.json'
    path_to_save_all_cwes = f'../results/{model_name}_{benchmark_name}_{method_name}_metrics_per_cwe.json'
    path_to_task1_bench = f'../data/{benchmark_name}/task1_code.jsonl'
    path_to_task2_bench = f'../data/{benchmark_name}/task2_code.jsonl'

    CWE_list = [
        'CWE-20', 'CWE-78', 'CWE-119', 'CWE-120', 'CWE-121',
        'CWE-122', 'CWE-190', 'CWE-476', 'CWE-762', 'CWE-787'
    ]

    # read in benchmark
    task1_bench = []
    with jsonlines.open(path_to_task1_bench, 'r') as reader:
        for obj in reader:
            task1_bench.append(obj)

    task2_bench = []
    with jsonlines.open(path_to_task2_bench, 'r') as reader:
        for obj in reader:
            task2_bench.append(obj)

    # read task1 and task2 results
    with open(task1_results_path, 'r') as f:
        task1_results = json.load(f)
        assert len(task1_results) == 1, 'task1_results length is not 1'
        task1_results = task1_results[0]['verbose']

    with open(task2_results_path, 'r') as f:
        task2_results = json.load(f)
        assert len(task2_results) == 1, 'task2_results length is not 1'
        task2_results = task2_results[0]['verbose']

    # calculate metrics for all CWE
    cal_all_cwes_metrics(task1_bench, task1_results, task2_bench, task2_results, CWE_list, path_to_save_all_cwes)

    # calculate total metrics
    cal_total_metrics(task1_results, task2_bench, task2_results, path_to_save_total_res)
    