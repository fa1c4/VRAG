import os
import json 
from tqdm import tqdm
from abc import ABC, abstractmethod
from typing import Optional, Union, List
import utils as metrics_lib
from utils import MetricsMapping as mm
from prompts import format_dataset, task_templates
from vrag_engine import adding_examples_to_dataset


class Agent(ABC):
    # currently, batch size is fixed to 1.
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


class TaskItem:
    # implementation of single task curation
    def __init__(self, name, dataset, metric_list):
        self.task_name = name
        self.dataset = dataset
        self.metrics = metric_list
        assert len(metric_list['single']) == len(metric_list['overall']), \
            f"Initialization failed in task {self.task_name}:number of single metric and overall metric must match. \
                Got {len(metric_list['single'])} single metrics and {len(metric_list['overall'])} overall metrics."
        
    def __len__(self):
        return len(self.dataset)
        
    def __iter__(self):
        self.current_data_index = 0
        return self
    
    def __next__(self):
        if self.current_data_index >= len(self.dataset):
            raise StopIteration("index out of dataset")
        
        data_item = self.dataset[self.current_data_index]
        id = data_item['id']
        question = {
            'system': data_item['system'],
            'user': data_item['user'],
            'example': '' if 'example' not in data_item.keys() else data_item['example']
        }
        answer = data_item['answer']
        self.current_data_index += 1

        return id, question, answer
    

class Tasks:
    def __init__(self, 
                 method = None, 
                 data_dir = None, 
                 task_no:Union[int, List[int], None] = None, 
                 emb_model:Optional[Agent] = None,
                 threshold:Optional[float] = 0.5):
        if task_no == None:
            self.task_no = [1,2]
        elif type(task_no) == int:
            self.task_no = [task_no]
        elif type(task_no) == list:
            if any(n > 2 or n < 1 for n in task_no):
                raise ValueError('task number list must not contain any index above 2 or under 1.')
            else:
                self.task_no = task_no
    
        task_selections = list(task_templates.keys())
        self.method = method
        self.data_dir = data_dir
        self.emb_model = emb_model
        self.threshold = threshold
        self.task_names = task_selections # [task_selections[task_no-1] for task_no in self.task_no]
        self.task_info = self._get_task_info()
        self.tasks = self._form_tasks()
    
    def _get_task_info(self):
        # self.task_name
        task_info = [task_templates[name] for name in self.task_names]
        # task_info = [None] + task_info # placebo
        return task_info
    
    def _load_dataset(self, task_no):
        path_to_dataset = os.path.join(self.data_dir, f'task{task_no}_code.jsonl')
        with open(path_to_dataset, 'r', encoding='utf-8') as f:
            print(task_no, self.task_names[task_no-1])
            # raw_dataset is list of dict
            raw_dataset = [json.loads(line) for line in f.readlines()]
            return raw_dataset
    
    def _form_dataset(self, task_no):
        # only a single task
        task_name = self.task_names[task_no-1]
        if task_no == 2:
            assert task_name == 'TypeInfer', f"task_no is {task_no}, but task_name is {task_name}"
        else:
            assert task_name == 'Existence', f"task_no is {task_no}, but task_name is {task_name}"

        raw_dataset = self._load_dataset(task_no)

        # implementing few-shot method by VRAG
        if self.method == 'few-shot':
            processed_dataset = adding_examples_to_dataset(self.emb_model, raw_dataset, self.threshold)
        else:
            processed_dataset = raw_dataset

        dataset = format_dataset(task_name, processed_dataset, self.method)
        return dataset 
    
    def _form_tasks(self):
        """
        form a seires of task LLM will work on.
        return:a list of object Task
        """
        all_tasks = []
        for no in self.task_no:          
            idx = no - 1
            dataset = self._form_dataset(no)
            task = TaskItem(name=self.task_info[idx]['Name'], dataset=dataset, metric_list=self.task_info[idx]['metrics'])
            all_tasks.append(task)
        
        return all_tasks
    
    def __len__(self):
        return len(self.tasks)
    
    def __iter__(self):
        self.task_idx = 0
        return self
    
    def __next__(self):
        if self.task_idx >= len(self.tasks):
            raise StopIteration("index out of tasks")
        
        task = self.tasks[self.task_idx]
        self.task_idx += 1
        return task


class Evaluator:
    # calculating and preserving metrics
    def __init__(self, answer_list, metric_dirs):
        self.metric_names = metric_dirs
        self.metric_funcs = {
            "single":self._choose_func(self.metric_names['single']),
            "overall":self._choose_func(self.metric_names['overall']),
        }
        self.answer_list = answer_list
    
    def _choose_func(self, metric_list):
        # choose eval funcs correspondent to metric str.
        return [mm[name] for name in metric_list]
    
    def _extract_single_metrics(self, single_metric, metric_name):
        # extract stable single metrics
        # *scalable function.
        if metric_name == 'hit':
            if single_metric == (1,0,0,0) or single_metric == (0,0,1,0):
                return 1
            else:
                return 0
        elif metric_name == 'Token Recall':
            return single_metric[0]
        else:
            return single_metric
        
    def remove_duplicate_metrics(self, data):
        seen_metrics = set()
        unique_data = []
        for item in data:
            metric = item['single metric']
            if metric not in seen_metrics:
                seen_metrics.add(metric)
                unique_data.append(item)        
        return unique_data

    def eval(self):
        """
        repo = {
            'task name':...,
            'verbose':[{
            'id':...,
            'gold':...,
            'metrics':[{
                'single name':...,
                'extracted_sys':...,
                'metric':...
                },...],
            'overall metric':{
                f"metric1":score,
                f"metric2":score
            }
        }
        """
        verbose_list = []  
        overall_scores = [[]] * len(self.metric_names['overall'])
        
        '''
        pair:
            {
                'id': id,      # need to keep id
                'prompt': prompt,
                'sys': sys_answer,
                'gold': gold
            }
        '''
        for pair in self.answer_list:
            id = pair['id']
            metrics = []
            for func_idx in range(len(self.metric_names['single'])):
                # single metric
                # single and overall metric from the same perspective share idx.
                single_func = self.metric_funcs['single'][func_idx]
                single_name = self.metric_names['single'][func_idx]
                score, filtered_answer = single_func(pair['sys'], pair['gold'])
                single_metric = self._extract_single_metrics(score, metric_name=single_name)
                overall_scores.append(score)
                metric = {
                    'single metric': single_name,
                    'extracted answer': filtered_answer,
                    'score': single_metric,
                    'prompt': pair['prompt'],
                    'original answer': pair['sys']
                }
                metrics.append(metric)
                overall_scores[func_idx].append(score)
                
            metrics = self.remove_duplicate_metrics(metrics)   # dedup
            # verbose list
            verbose_list.append({
                'id': id,
                'gold': pair['gold'],
                'metrics': metrics
            })
        
        # calculate overall metrics
        overall_metric_list = []
        for func_idx in range(len(self.metric_names['overall'])):
            overall_func = self.metric_funcs['overall'][func_idx]
            overall_name = self.metric_names['overall'][func_idx]
            scores = overall_scores[func_idx]
            overall_metric = overall_func(scores)
            overall_metric_list.append({
                overall_name: overall_metric
            }) 
        
        repo = {
            'overall metrics': overall_metric_list,
            'verbose': verbose_list
        }
        
        return repo


class VulDT_Engine:
    def __init__(
        self,
        model: Agent,
        task_and_metrics: Tasks,
        emb_model: Optional[Agent] = None, 
        verbose: bool = True,
        save_path: Optional[str] = None,
        result_name: Optional[str] = 'evaluation_report.json'
    ):
        self.model = model
        self.emb_model = emb_model
        self.tasks = task_and_metrics
        self.verbose = verbose
        self.save_path = save_path
        self.result_name = result_name

    def _run_single_task(self, task:TaskItem):
        """
        run on single task
        return : answer_list(list)
        """
        answer_list = []
        for id, prompt, gold in tqdm(task, desc='generating results'):
            sys_answer = self.model(prompt)
            answer_list.append({
                'id': id,      # need to keep id
                'prompt': prompt,
                'sys': sys_answer,
                'gold': gold
            })
        return answer_list

    def run_all_tasks(self):
        evaluators = []
        for task in self.tasks:
            print(f'Running task : {task.task_name}')
            metrics = task.metrics    # list
            answer_list = self._run_single_task(task)
            evaluators.append((task.task_name, Evaluator(answer_list, metrics)))
        
        return evaluators
        
    def eval(self, evaluators):
        metric_repos = []
        for task_name, evaluator in evaluators:
            repo = evaluator.eval()
            repo['task name'] = task_name
            metric_repos.append(repo)
        
        return metric_repos
    
    def simplify_repo(self, repos):
        """
        use it if verbose is False
        """
        simp_repo = dict()
        for repo in repos:
            simp_repo[repo['task name']] = repo['overall metric']
        return simp_repo
    
    def run(self):
        # formally run the whole bench
        evaluators = self.run_all_tasks()
        metric_repos = self.eval(evaluators=evaluators)
        if self.verbose == False:
            metric_repos = self.simplify_repo(metric_repos)
        if self.save_path is None:
            print(metric_repos)
        else:
            if os.path.exists(self.save_path) == False:
                os.makedirs(self.save_path)
            result_name = self.result_name
            result_path = os.path.join(self.save_path, result_name)
            with open(result_path, 'w', encoding='utf-8') as f:
                json.dump(metric_repos, f, indent=2)
                print(f'evaluation reports saved to {result_path}')
