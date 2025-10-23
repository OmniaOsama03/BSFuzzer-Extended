import json  
import pandas as pd  
DEFAULT_SYSTEM_PROMPT = '把在>>>和<<<中的内容翻译成[[和]]中的语言 '  
def get_example(language, origin, target):  
    return {  
        "messages": [  
            {"role": "system", "content": DEFAULT_SYSTEM_PROMPT},  
            {"role": "user", "content": f'[[{language}]], >>>{origin}<<<'},  
            {"role": "assistant", "content": target},  
        ]  
    }  
if __name__ == "__main__":  
    df = pd.read_excel("/home/yangting/Documents/Semanteme/data/translate.xlsx")  
    with open("/home/yangting/Documents/Semanteme/data/train.jsonl", "w", encoding="utf8") as f:  
        for i, row in list(df.iterrows()):  
            origin = row["origin"]  
            target = row["target"]  
            # print(origin)
            example = get_example('en', origin, target)  
            example_str = json.dumps(example,ensure_ascii=False)  
            f.write(example_str + "\n")


