from liquid import Template 


task_templates = {
    "Existence": {
        "Name":"Vulnerability Existence Detection",
        "system":"Assuming you are an experienced code vulnerability analyst and the following code may have vulnerabilities.",
        "question":"Is the code vulnerable?(YES/NO)",
        "restriction":"Your answer should either be 'YES' or 'NO' only.",
        "metrics":{
            "single" : ['hit','hit'],
            "overall" : ['Accuracy','F1-Score']
        }
    },
    "TypeInfer": {
        "Name":"Vulnerability Type Inference",
        "system":"You are an outstanding code vulnerability analyst and expert in single-choice questions.You are only able to pick up 1 answer from given choices.",
        "question":"What is the vulnerability type of the code?(A/B/C/D/E)",
        "restriction":"output 'A.' or 'B.' or 'C.' or 'D.' or 'E.' only.",
        "metrics":{
            "single" : ['Moderate Evaluation Score','Strict Evaluation Score'],
            "overall" : ['Avg Moderate Evaluation Score','Avg Strict Evaluation Score']
        }
    }
}

def format_dataset(task_name, raw_dataset, method=None):
    general_prompt = Template("{{ question }}\n{{example_with_restriction}}\n{{ code }}\n{{ restriction }}\n{{cot_with_restriction}}")
    # vrag_prompt = Template("{{ question }}\n{{example_with_restriction}}\n{{ code }}\n{{ restriction }}\n{{cot_with_restriction}}")
    dataset=[]
    
    template=task_templates[task_name]
    for raw_sample in raw_dataset:
        if task_name=='TypeInfer':
            user_prompt=general_prompt.render(question=template['question'],
                                              code=raw_sample['selection'] + raw_sample['code'],
                                              restriction=template['restriction'],
                                              cot_with_restriction='',
                                              example_with_restriction='')   
        else:
            user_prompt=general_prompt.render(question=template['question'],
                                              code=raw_sample['code'],
                                              example_with_restriction='',
                                              cot_with_restriction='',
                                              restriction=template['restriction'])
               
        dataset.append({
            'id':raw_sample['idx'],
            'system':template['system'],
            'user':user_prompt,
            'answer':raw_sample['answer']
        })

    return dataset
