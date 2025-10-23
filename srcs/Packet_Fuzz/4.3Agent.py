import os
import sys
import json
import re

from time import sleep


sys.path.insert(0,os.path.dirname(os.path.dirname(os.path.abspath(__file__)))+"/../../")

from langchain.embeddings import OpenAIEmbeddings
from langchain.vectorstores import FAISS
from langchain.chains import RetrievalQA
from langchain.agents import initialize_agent, Tool, AgentType
from langchain.prompts import PromptTemplate

from BSFuzz.srcs.llm_model.ModConf import ModelConfig
from BSFuzz.srcs.prompt.SemFieldRspPrompt import get_field_prompt
from BSFuzz.srcs.prompt.SemStateRspPrompt import get_state_prompt
from pydantic import BaseModel


class FieldAnalysis(BaseModel):
  Mutation: str
  Mutation_RSP: str
  Judgment: str
  Explanation: str
class StateAnalysis(BaseModel):
  Input: str
  Output: str
  Judgment: str
  Analysis: str





with open("/home/yangting/Documents/Semantic/config/semresult_config.json", "r") as file:
    config = json.load(file)
    field_model_config = ModelConfig(config.get("llm", {}).get("field_model_provider"))
    state_model_config = ModelConfig(config.get("llm", {}).get("state_model_provider"))
    base_model_config = ModelConfig(config.get("llm", {}).get("base_model_provider"))


    field_model = config.get("llm", {}).get("model")
    state_model = config.get("llm", {}).get("state_model")
    base_model = config.get("llm", {}).get("base_model")
# 
    field_model_config.update_config({"model":config.get("llm", {}).get("field_model"),"temperature":config.get("llm", {}).get("temperature"),})
    state_model_config.update_config({"model":config.get("llm", {}).get("state_model"),"temperature":config.get("llm", {}).get("temperature"),})
    base_model_config.update_config({"model":config.get("llm", {}).get("base_model"),"temperature":config.get("llm", {}).get("temperature"),})
    field_llm = field_model_config.get_llm()
    state_llm = state_model_config.get_llm()
    base_llm = base_model_config.get_llm()
    smp_faiss_index_path = config.get("faiss_index_path", {}).get("smp_faiss_index_path")
    l2cap_faiss_index_path = config.get("faiss_index_path", {}).get("l2cap_faiss_index_path")
    att_faiss_index_path = config.get("faiss_index_path", {}).get("att_faiss_index_path")
    ll_faiss_index_path = config.get("faiss_index_path", {}).get("ll_faiss_index_path")
    seed_result_file_path = config.get("semresult", {}).get("seed_result_file_path")
    answer_result_file_path = config.get("semresult", {}).get("answer_result_file_path")


def load_vector_store(faiss_index_path):
    embeddings = OpenAIEmbeddings()
    return FAISS.load_local(
        faiss_index_path,
        embeddings,
        allow_dangerous_deserialization=True
    )

# Step 4: Create a retrieval tool for the agent
def create_smp_retrieval_tool(vector_store, k_value=10):
    prompt_template = """
    You are a Bluetooth SMP (Security Manager Protocol) expert analyzing the Bluetooth Core Specification.
    Use the provided context from the specification to answer questions about SMP protocol.
    Focus on security features, pairing procedures, and authentication mechanisms.
    If asked about protocol violations or errors, identify the issue, explain its implications,
    and suggest mitigations. Use chain-of-thought reasoning to break down your analysis.
    
    Context: {context}
    Question: {question}
    
    Answer in a clear, concise, and technical manner.
    """
    prompt = PromptTemplate(
        template=prompt_template,
        input_variables=["context", "question"]
    )
    
    qa_chain = RetrievalQA.from_chain_type(
        llm=base_llm,
        chain_type="stuff",
        retriever=vector_store.as_retriever(search_kwargs={"k": k_value}),
        chain_type_kwargs={"prompt": prompt}
    )
    
    return Tool(
        name="SMP_Spec_Retriever",
        func=qa_chain.invoke,
        description="Retrieves and analyzes information specific to Bluetooth SMP protocol from the specification."
    )

def create_l2cap_retrieval_tool(vector_store, k_value=10):
    prompt_template = """
    You are a Bluetooth L2CAP (Logical Link Control and Adaptation Protocol) expert analyzing the Bluetooth Core Specification.
    Use the provided context from the specification to answer questions about L2CAP protocol.
    Focus on channel management, segmentation and reassembly, and multiplexing capabilities.
    If asked about protocol violations or errors, identify the issue, explain its implications,
    and suggest mitigations. Use chain-of-thought reasoning to break down your analysis.
    
    Context: {context}
    Question: {question}
    
    Answer in a clear, concise, and technical manner.
    """
    prompt = PromptTemplate(
        template=prompt_template,
        input_variables=["context", "question"]
    )
    
    qa_chain = RetrievalQA.from_chain_type(
        llm=base_llm,
        chain_type="stuff",
        retriever=vector_store.as_retriever(search_kwargs={"k": k_value}),
        chain_type_kwargs={"prompt": prompt}
    )
    
    return Tool(
        name="L2CAP_Spec_Retriever",
        func=qa_chain.invoke,
        description="Retrieves and analyzes information specific to Bluetooth L2CAP protocol from the specification."
    )

def create_att_retrieval_tool(vector_store, k_value=10):
    prompt_template = """
    You are a Bluetooth ATT (Attribute Protocol) expert analyzing the Bluetooth Core Specification.
    Use the provided context from the specification to answer questions about ATT protocol.
    Focus on attribute operations, data formats, and error handling procedures.
    If asked about protocol violations or errors, identify the issue, explain its implications,
    and suggest mitigations. Use chain-of-thought reasoning to break down your analysis.
    
    Context: {context}
    Question: {question}
    
    Answer in a clear, concise, and technical manner.
    """
    prompt = PromptTemplate(
        template=prompt_template,
        input_variables=["context", "question"]
    )
    
    qa_chain = RetrievalQA.from_chain_type(
        llm=base_llm,
        chain_type="stuff",
        retriever=vector_store.as_retriever(search_kwargs={"k": k_value}),
        chain_type_kwargs={"prompt": prompt}
    )
    
    return Tool(
        name="ATT_Spec_Retriever",
        func=qa_chain.invoke,
        description="Retrieves and analyzes information specific to Bluetooth ATT protocol from the specification."
    )

def create_ll_retrieval_tool(vector_store, k_value=10):
    prompt_template = """
    You are a Bluetooth LL (Link Layer) expert analyzing the Bluetooth Core Specification.
    Use the provided context from the specification to answer questions about Link Layer protocol.
    Focus on connection establishment, packet formats, and state machines.
    If asked about protocol violations or errors, identify the issue, explain its implications,
    and suggest mitigations. Use chain-of-thought reasoning to break down your analysis.
    
    Context: {context}
    Question: {question}
    
    Answer in a clear, concise, and technical manner.
    """
    prompt = PromptTemplate(
        template=prompt_template,
        input_variables=["context", "question"]
    )
    
    qa_chain = RetrievalQA.from_chain_type(
        llm=base_llm,
        chain_type="stuff",
        retriever=vector_store.as_retriever(search_kwargs={"k": k_value}),
        chain_type_kwargs={"prompt": prompt}
    )
    
    return Tool(
        name="LL_Spec_Retriever",
        func=qa_chain.invoke,
        description="Retrieves and analyzes information specific to Bluetooth Link Layer protocol from the specification."
    )

# Step 5: Initialize the agent
def create_agent(llm,k_value=10):
    tools = []
    
    smp_vector_store = load_vector_store(smp_faiss_index_path)
    l2cap_vector_store = load_vector_store(l2cap_faiss_index_path)
    att_vector_store = load_vector_store(att_faiss_index_path)
    ll_vector_store = load_vector_store(ll_faiss_index_path)
    

    smp_tool = create_smp_retrieval_tool(smp_vector_store, k_value)
    l2cap_tool = create_l2cap_retrieval_tool(l2cap_vector_store, k_value)
    att_tool = create_att_retrieval_tool(att_vector_store, k_value)
    ll_tool = create_ll_retrieval_tool(ll_vector_store, k_value)
    
    tools.append(smp_tool)
    tools.append(l2cap_tool)
    tools.append(att_tool)
    tools.append(ll_tool)
    
    # Initialize the agent with ReAct framework
    agent = initialize_agent(
        tools=tools,
        llm=llm,
        agent=AgentType.ZERO_SHOT_REACT_DESCRIPTION, 
        verbose=True
    )
    return agent

def read_logs(log_path):
        logs = []
        
        with open(log_path, 'r') as f:
            # 每行都是一个独立的JSON对象
            for line in f:
                try:
                    log_entry = json.loads(line.strip())
                    logs.append(log_entry)
                except json.JSONDecodeError as e:
                    print(f"解析JSON行时出错: {e}")
                    continue
        
        print(f"成功读取 {len(logs)} 条日志记录")
        return logs

def write_result(result):
    with open(answer_result_file_path, "a") as file:
        file.write(result)
        file.write('\n')

# Step 6: Main function to run the agent
def main():
    seed_result_list = read_logs(seed_result_file_path)
    log = 0
  
    index = 0
    while index < len(seed_result_list):
        
        seed_result = seed_result_list[index]
        if index < log:
      
            index += 1
            continue
        try:
            if seed_result['mutation'] is not None:
                #seed mutation
                agent = create_agent(field_llm,k_value=20)
                query = get_field_prompt(INSEQ=seed_result['base_path'], OUTSEQ=seed_result['outputs'], MUTINF=seed_result['mutation'], RSP=seed_result['fuzz_result'])
                response = agent.invoke(query)
                final_result = response['output'].replace("```json\n", "").replace("```", "")
                
                final_result = json.dumps({"log_id":index, "analysis":final_result})
                write_result(final_result)
                index += 1
                print(f"完成第{index}个种子")
                

            else:
                #state mutation
                agent = create_agent(state_llm,k_value=20)
                query = get_state_prompt(INSEQ=seed_result['base_path'], OUTSEQ=seed_result['outputs'])

                response = agent.invoke(query)
                final_result = response['output'].replace("```json\n", "").replace("```", "")
              
                final_result = json.dumps({"log_id":index, "analysis":final_result})
                write_result(final_result)
      
                index += 1
                print(f"完成第{index}个种子")
        except ValueError as e:
            try:
                # 使用正则表达式找到 JSON 部分
                # 查找 ```json 和 ``` 之间的内容
                error_message = str(e)
                json_match = re.search(r'```json\n(.*?)\n```', error_message, re.DOTALL)
                #replace("```json\n", "").replace("```", "")
                if json_match:
                    final_result = json_match.group(1).replace("```json\n", "").replace("```", "")
                    final_result = json.dumps({"log_id":index, "analysis":final_result})
                    write_result(final_result)
             
                    index += 1
                    print(f"完成第{index}个种子")
            except Exception as e:
                #写一个空json
                final_result = json.dumps({"log_id":index, "error":str(e)})
                write_result(final_result)
                print(f"第{index}个种子出错")
            

                
        except Exception as e:

            sleep(10)
            final_result = json.dumps({"log_id":index, "error":str(e)})
            write_result(final_result)
            print(f"第{index}个种子出错")
        

        # print(response['output'])
        # with open(answer_result_file_path, "a") as file:
        #     # 创建标准的JSON对象
        #     output_json = {
        #         "analysis": response['output'].replace("```json\n", "").replace("```", ""),
        #         "timestamp": seed_result.get('time', ""),
        #         "log_id": seed_result.get('log', 0)
        #     }
        #     json.dump(output_json, file)
        #     file.write('\n')

if __name__ == "__main__":
    main()