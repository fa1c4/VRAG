'''
vrag enhancing vuln detection by providing vulnerabilities code snippets similar to target code in prompts
'''
import os
import requests
from openai import OpenAI
from tqdm import tqdm
import torch
from llm2vec import LLM2Vec
from vrag_engine import VRAG_Engine
from vuldt import Tasks, Agent, VulDT_Engine


debug_flag = True # True | False
glb_failed_cnt = 0
class OpenAIAgent(Agent):
    def __init__(self):
        self.api_key = os.getenv("OPENAI_API_KEY")
        self.temperature = 0.1
        if not self.api_key:
            raise ValueError("OpenAI API key not found. Please set it in the environment variables.")
        
    def __call__(self, prompt):
        global glb_failed_cnt
        if not isinstance(prompt, dict):
            raise ValueError("Prompt must be a dictionary with 'system' and 'user' keys.")
        
        system_message = prompt.get("system", "")
        user_message = prompt.get("user", "")
        examples_message = prompt.get("examples", "") # few-shot examples
        
        if not user_message:
            raise ValueError("User message must be provided in the prompt.")
    
        # url = "https://api.openai.com/v1/chat/completions"
        url = "https://gptgod.cloud/v1/chat/completions"
        
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}"
        }

        try:
            data = {
                "model": "gpt-3.5-turbo",
                "messages": [
                    {"role": "system", "content": system_message},
                    {"role": "system", "content": examples_message},
                    {"role": "user", "content": user_message}
                ],
                "temperature": self.temperature
            }

            if debug_flag:
                print('data:', data)
            
            response = requests.post(url, headers=headers, json=data)
            return response.json()['choices'][0]['message']['content']
        except Exception as e:
            glb_failed_cnt += 1
            print("failed request", data)
            return ""


if __name__ == '__main__':
    gpt_model = OpenAIAgent()

    path_to_all_fixes_data = '../data/all_fixes_data_with_SHA256.json'
    path_to_base_model = '../../Models/LLM2Vec-Meta-Llama-3-8B-Instruct-mntp'   
    # load embedding model
    l2v = LLM2Vec.from_pretrained(
        path_to_base_model,
        # peft_model_name_or_path=path_to_peft_model,
        device_map="cuda" if torch.cuda.is_available() else "cpu",
        torch_dtype=torch.bfloat16,
        local_files_only=True
    )

    # set few-shot method to use VRAG
    tasks = Tasks(data_dir='../data/VulDetectBench/', method='few-shot', task_no=[1,2], emb_model=l2v)
    engine = VulDT_Engine(model=gpt_model, save_path='../result/', task_and_metrics=tasks)
    engine.run()
    print('failed_cnt:', glb_failed_cnt)
