import os
from dotenv import load_dotenv


def format_prompt_1(acCrime):
    prompt = f"""
    Assume you are a highly experienced criminal defense lawyer specializing in juvenile cases.
    Provided with the Crime Accusation against a Minor below at the end:
    
    You are required to provide the final essay that minor should write to save himself.

    you can analysis your case considering these points but not necessary as i just need an essay:
        Relevant Legal Principles: Enumerate, point by point and in a formatted manner, the key legal principles, statutes, precedents and juvenile justice procedures applicable to the given accusation against a minor.
        Missing Information: List any crucial information, evidence, witness accounts or evaluations (e.g., psychological, circumstantial) lacking that could aid in the minor's defense.
        Potential Challenges: Outline the potential legal challenges, prosecution arguments, or aggravating evidence that could be raised against the minor defendant.
        Case Evaluation: Assess the strength of the minor's defense on a scale of 1 to 10, factoring in the accusation details, legal principles, and mitigating circumstances. Show your criteria and calculations.
        Strategic Recommendations: Provide specific recommendations on the legal strategy, rehabilitative measures, alternative sentencing options, or other actions to pursue in the minor's best interests and potential reform.
        

    Crime Accusation Against Minor: "{acCrime}"
    
    Please ensure client confidentialit and approach this case with a focus on rehabilitation and the minor's well-being alongside a strong legal defense. Give me the final essay that the client should write.
    
  
"""
    
    return prompt


 
# loading env varaibles
load_dotenv()
# REPLACE WITH YOUR HUGGING FACE ACCOUNT TOKEN ( Go to settings and get access token from hugging face)
hf_token=os.getenv('HF_TOKEN')

# querying
def query(payload):
    
    import requests

    # Replace API URL with your LLM API URL ( from hugging face. i.e. )
    # for example HF_LLM_INFERENCE_CHECKPOINT='https://api-inference.huggingface.co/models/mistralai/Mistral-7B-Instruct-v0.2'
    # API_URL='https://api-inference.huggingface.co/models/mistralai/Mistral-7B-Instruct-v0.2'
    API_URL="https://api-inference.huggingface.co/models/mistralai/Mixtral-8x7B-Instruct-v0.1"
    # API_URL = os.getenv('HF_LLM_INFERENCE_CHECKPOINT')

    headers = {"Authorization": "Bearer "+hf_token}
    
    # retriving response
    response = requests.post(API_URL, headers=headers, json=payload)
    return response.json()

def prompt_format_2(acCrime):
  formatted_prompt=format_prompt_1(acCrime)
  prompt='<s>[INST] '+formatted_prompt+'\n [/INST] Model answer</s>'
  return prompt

def infer(acCrime):
  try:
      print("going to infer")

      prompt=prompt_format_2(acCrime)
      
      # print("generated prompt",prompt)
      output = query({
          "inputs": prompt,
          "parameters": 
        {
          "contentType": "application/json",
          "max_tokens": 30000,
          "max_new_tokens": 5000,
          "return_full_text": False
        }
      })

      return output[0]['generated_text']
  except Exception as e:
        print(f"An error occurred: {e}")
        return f"could not generate answer Due to Error, please try after some time ,{e} "  