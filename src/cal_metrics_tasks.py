'''
input: task1 (task2) vulnerabilities detection results json file path
output: n types of vulnerabilities accuracy, precision, recall, f1-score
'''
import json
import jsonlines
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report,
)


# This function calculates the accuracy, precision, recall, and F1 score for a binary classification task.
def calculate_binary_metrics(y_true, y_pred):
    accuracy = accuracy_score(y_true, y_pred)
    precision = precision_score(y_true, y_pred, average='macro')
    recall = recall_score(y_true, y_pred, average='macro')
    f1 = f1_score(y_true, y_pred, average='macro')
    report = classification_report(y_true, y_pred)

    return {
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "report": report
    }

# This function calculates the accuracy, precision, recall, and F1 score for a multi-class classification task.
def calculate_multiclasses_metrics(y_true, y_pred):
    accuracy = accuracy_score(y_true, y_pred)
    precision = precision_score(y_true, y_pred, average='macro')
    recall = recall_score(y_true, y_pred, average='macro')
    f1 = f1_score(y_true, y_pred, average='macro')
    report = classification_report(y_true, y_pred)

    return {
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "report": report
    }

# This function extracts the true labels and predicted labels from the task1 results.
def get_task1_y_true_and_y_pred(task1_results):
    y_true, y_pred = [], []
    for result in task1_results:
        # skip failed result
        if len(result['metrics'][0]['original answer']) == 0:
            continue

        gold = result['gold']
        assert len(result['metrics']) == 1, "metrics should be one dict"

        pred = result['metrics'][0]['extracted answer']
        assert pred == result['metrics'][0]['original answer'] or pred in result['metrics'][0]['original answer'], \
                    f"[-] id-{result['id']}: pred and original answer should be the same"

        y_true.append(gold)
        y_pred.append(pred)

    assert len(set(y_true)) == 1 or set(y_true) == set(y_pred), f"y_true: {set(y_true)} y_pred: {set(y_pred)}"
    assert len(set(y_true)) == 1 or set(y_true) == set(['YES', 'NO']), "y_true should be in [YES, NO]"
    print(f"[-] task1: {len(y_true)} samples valid")
    return y_true, y_pred

# This function extracts the true labels and predicted labels from the task2 results.
def get_task2_y_true_and_y_pred(task2_results):
    y_true, y_pred = [], []
    for result in task2_results:
        # skip failed result
        check_tmp = result['metrics'][0]['original answer']
        if len(check_tmp) == 0 or len(check_tmp) > 2:
            continue
        
        # skip unnormalized result
        if not (check_tmp.startswith('A') or check_tmp.startswith('B') or check_tmp.startswith('C') or check_tmp.startswith('D') or check_tmp.startswith('E')):
            continue
        
        gold = result['gold'].split('.')[0]
        assert len(result['metrics']) == 2, "metrics should be one dicts"

        # pred = result['metrics'][0]['extracted answer']
        # assert pred == result['metrics'][0]['original answer'].replace('.', ''), f"[-] id-{result['id']}: pred and original answer should be the same"
        pred = check_tmp.split('.')[0]
        assert pred in ['A', 'B', 'C', 'D', 'E'], f"[-] id-{result['id']}: pred should be in [A, B, C, D, E]"

        y_true.append(gold)
        y_pred.append(pred)

    assert set(y_true) == set(y_pred), f"y_true: {set(y_true)} y_pred: {set(y_pred)}"
    assert set(y_true) == set(['A', 'B', 'C', 'D', 'E']), "y_true should be in [A, B, C, D, E]"
    print(f"[-] task2: {len(y_true)} samples valid")
    return y_true, y_pred

# This function extracts the CWE list from the task results.
def get_task_CWE_list(task_results):
    CWE_list = []
    for result in task_results:
        # skip failed result
        if len(result['metrics'][0]['original answer']) == 0:
            continue

        gold = result['gold']

        CWE_list.append('CWE-' + gold)

    assert len(set(CWE_list)) > 0, f"[-] CWE_list is empty"
    print(f"[-] CWE_list: {set(CWE_list)}")
    return list(set(CWE_list))

# This function extracts the CWE by id from the task benchmark.
def get_CWE_by_id(task_bench, res_id):
    for example in task_bench:
        if example['idx'] == res_id:
            return example['cwe']
    print(f"[-] CWE not found for id: {res_id}")
    exit(-2)

# This function calculates the metrics for task1.
def cal_task1_metrics(task_bench, task_results, CWE_list):
    all_vuln_lists = []
    for cwe_id in CWE_list:
        cwe = cwe_id.replace('CWE-', '')
        vuln_list = []
        for result in task_results:
            res_id = result['id']
            cwe_ground = get_CWE_by_id(task_bench, res_id)
            if cwe_ground == cwe:
                vuln_list.append(result)
        all_vuln_lists.append(vuln_list)
    assert len(all_vuln_lists) == len(CWE_list), f"[-] all_vuln_lists length should be equal to CWE_list length, {len(all_vuln_lists)} != {len(CWE_list)}"

    for i, vuln_list in enumerate(all_vuln_lists):
        cwe_id = CWE_list[i]
        cwe = cwe_id.replace('CWE-', '')
        print(f"[-] CWE-{cwe} vuln list length: {len(vuln_list)}")
        if len(vuln_list) == 0:
            continue

        y_true, y_pred = get_task1_y_true_and_y_pred(vuln_list)
        task1_metrics = calculate_binary_metrics(y_true, y_pred)
        print(f"[-] CWE-{cwe} task1 metrics: {task1_metrics}")
        
        with open(f'../results/{model_name}_{benchmark_name}_{method_name}_task1_metrics_{cwe_id}.json', 'w') as f:
            json.dump(task1_metrics, f, indent=4)

        print(f"[-] CWE-{cwe} task1 metrics saved to {f.name}")

# This function calculates the metrics for task2.
def cal_task2_metrics(task_bench, task_results, CWE_list):
    all_vuln_lists = []
    for cwe_id in CWE_list:
        cwe = cwe_id.replace('CWE-', '')
        vuln_list = []
        for result in task_results:
            res_id = result['id']
            cwe_ground = get_CWE_by_id(task_bench, res_id)
            if cwe_ground == cwe:
                vuln_list.append(result)
        all_vuln_lists.append(vuln_list)
    assert len(all_vuln_lists) == len(CWE_list), f"[-] all_vuln_lists length should be equal to CWE_list length, {len(all_vuln_lists)} != {len(CWE_list)}"

    for i, vuln_list in enumerate(all_vuln_lists):
        cwe_id = CWE_list[i]
        cwe = cwe_id.replace('CWE-', '')
        print(f"[-] CWE-{cwe} vuln list length: {len(vuln_list)}")
        if len(vuln_list) == 0:
            continue

        y_true, y_pred = get_task2_y_true_and_y_pred(vuln_list)
        task2_metrics = calculate_multiclasses_metrics(y_true, y_pred)
        print(f"[-] CWE-{cwe} task2 metrics: {task2_metrics}")

        with open(f'../results/{model_name}_{benchmark_name}_{method_name}_task2_metrics_{cwe_id}.json', 'w') as f:
            json.dump(task2_metrics, f, indent=4)

        print(f"[-] CWE-{cwe} task2 metrics saved to {f.name}")


if __name__ == '__main__':
    # paths to results json
    model_name = 'deepseek-reasoner' # 'gpt-3.5-turbo' | 'gpt-4-turbo' | 'gpt-4o' | 'deepseek-chat' | 'deepseek-reasoner' | 'deepseek-coder'
    method_name = 'zero-shot' # few-shot | zero-shot
    benchmark_name = 'CWEClassesBench' # 'CWEClassesBench' | 'RealVulBench'
    threshold_val = 0.1 # threshold value for task
    task1_results_path = f'../results/{model_name}_{benchmark_name}_{method_name}_threshold{threshold_val}_task1_eval.json'
    task2_results_path = f'../results/{model_name}_{benchmark_name}_{method_name}_threshold{threshold_val}_task2_eval.json'
    path_to_save_classes_statistics = f'../results/{model_name}_{benchmark_name}_{method_name}_classes_statistics.json'
    path_to_task1_bench = f'../data/{benchmark_name}/task1_code.jsonl'
    path_to_task2_bench = f'../data/{benchmark_name}/task2_code.jsonl'

    # CWE_lists = [
    #     'CWE-20', 'CWE-78', 'CWE-119', 'CWE-120', 'CWE-121',
    #     'CWE-122', 'CWE-190', 'CWE-476', 'CWE-762', 'CWE-787'
    # ]

    # load task1 and task2 benchmarks jsonlines
    task1_bench = []
    with jsonlines.open(path_to_task1_bench, 'r') as reader:
        for obj in reader:
            task1_bench.append(obj)
    
    task2_bench = []
    with jsonlines.open(path_to_task2_bench, 'r') as reader:
        for obj in reader:
            task2_bench.append(obj)

    # load task1 and task2 results
    with open(task1_results_path, 'r') as f:
        task1_results = json.load(f)
        assert len(task1_results) == 1, "task1_results should contain only one element"
        task1_results = task1_results[0]
        task1_results = task1_results['verbose']

    with open(task2_results_path, 'r') as f:
        task2_results = json.load(f)
        assert len(task2_results) == 1, "task2_results should contain only one element"
        task2_results = task2_results[0]
        task2_results = task2_results['verbose']

    # divide task1 and task2 results into classes
    # task1_CWE_list = get_task_CWE_list(task1_results)
    # task2_CWE_list = get_task_CWE_list(task2_results)

    # calculate all vuln types of task1 metrics 
    # cal_task1_metrics(task1_bench, task1_results, task1_CWE_list)
    # calculate all vuln types of task2 metrics
    # cal_task2_metrics(task2_bench, task2_results, task2_CWE_list)

    # get task1 y_true and y_pred
    y_true_task1, y_pred_task1 = get_task1_y_true_and_y_pred(task1_results)
    # get task2 y_true and y_pred
    y_true_task2, y_pred_task2 = get_task2_y_true_and_y_pred(task2_results)

    # Calculate metrics for task 1
    task1_metrics = calculate_binary_metrics(y_true_task1, y_pred_task1)
    print("Task 1 Metrics:", task1_metrics)

    # Calculate metrics for task 2
    task2_metrics = calculate_multiclasses_metrics(y_true_task2, y_pred_task2)
    print("Task 2 Metrics:", task2_metrics)

    # Save task1 and task2 metrics to json
    with open(path_to_save_classes_statistics, 'w') as f:
        json.dump({
            "task1_metrics": task1_metrics,
            "task2_metrics": task2_metrics
        }, f, indent=4)

    print(f"Task 1 and Task 2 metrics saved to {path_to_save_classes_statistics}")
