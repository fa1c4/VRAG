'''
code for gpts vulnerabilities detection experiments
models: gpt-3.5-turbo, gpt-4-turbo, gpt-4o
'''

import openai
from openai import OpenAI
from vuldetectbench.generation import Tasks, Agent, VulDetectBench_Engine
import os
import requests


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
                "model": "gpt-4o",
                "messages": [
                    {"role": "system", "content": system_message},
                    {"role": "user", "content": user_message}
                ],
                "temperature": self.temperature
            }
            
            response = requests.post(url, headers=headers, json=data)
            return response.json()['choices'][0]['message']['content']
        except Exception as e:
            glb_failed_cnt += 1
            print("failed request", data)
            return ""
        
        
if __name__=='__main__':
    gpt_model=OpenAIAgent()
    tasks=Tasks(data_dir='/data/zym/VulDetectBench/dataset/test', method='few-shot', task_no=[1,2])
    engine=VulDetectBench_Engine(model=gpt_model, save_path='./', task_and_metrics=tasks)
    engine.run()
    print('failed_cnt:', glb_failed_cnt)
