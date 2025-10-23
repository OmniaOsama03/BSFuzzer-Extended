import os
import sys
import json
import re
from regex import E
from time import sleep
import xml.etree.ElementTree as ET

sys.path.insert(0,os.path.dirname(os.path.dirname(os.path.abspath(__file__)))+"/../../")

from langchain.embeddings import OpenAIEmbeddings
from langchain.vectorstores import FAISS
from langchain.chains import RetrievalQA
from langchain.agents import initialize_agent, Tool, AgentType
from langchain.prompts import PromptTemplate
from uuid import uuid4
from BSFuzz.srcs.llm_model.ModConf import ModelConfig
# from BSFuzz.srcs.prompt.SemFieldRspPrompt import get_field_prompt
from BSFuzz.srcs.prompt.SemExpectFieldRsp import get_prompt





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
    sem_info_file_path = config.get("sem_info", {}).get("sem_info_file_path")


def load_sem_info(sem_info_file_path):
    tree = ET.parse(sem_info_file_path)
    root = tree.getroot()
    return root

def get_packet_fields(sem_info_file_path):
    tree = ET.parse(sem_info_file_path)
    root = tree.getroot()
    field_info = []
    for packet in root.findall('.//packet'):
        packet_name = packet.get('name')
        for field in packet.findall('.//field'):
            field_name = field.get('name')
            semantic = field.find('semantic')
            defined_values = field.find('defined_values')
            field_info.append({
                'layer_name': packet_name,
                'field_name': field_name,
                'semantic': semantic.text if semantic is not None else None,
                'defined_values': defined_values.text if defined_values is not None else None
            })
    return field_info

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
    try:
        with open(log_path, 'r', encoding='utf-8') as f:
            content = f.read().strip()
            # 如果文件内容为空，返回空列表
            if not content:
                return []
            
            # 尝试解析整个文件内容作为一个JSON对象
            try:
                result = json.loads(content)
                return [result]  # 返回包含单个JSON对象的列表
            except json.JSONDecodeError as e:
                print(f"解析完整JSON失败: {e}")
                # 如果完整解析失败，尝试逐行解析
                results = []
                current_json = ""
                for line in content.split('\n'):
                    line = line.strip()
                    if not line:
                        continue
                    current_json += line
                    try:
                        # 尝试解析当前累积的JSON
                        json_obj = json.loads(current_json)
                        results.append(json_obj)
                        current_json = ""  # 重置当前JSON
                    except json.JSONDecodeError:
                        # 如果解析失败，继续累积下一行
                        continue
                
                if results:
                    print(f"成功读取 {len(results)} 个JSON对象")
                    return results
                else:
                    print("无法解析任何JSON对象")
                    return []
    except Exception as e:
        print(f"读取文件失败: {e}")
        return []

def write_result(result):
    with open(answer_result_file_path, "a") as file:
        file.write(result)
        file.write('\n')

# Step 6: Main function to run the agent
def main():
        field_info = get_packet_fields(sem_info_file_path)
        index = 0
        log_path = "/home/yangting/Documents/Semantic/result/log_file/Esp32/answer_result1.json"
        logs = read_logs(log_path)


        while index < len(field_info):
            seed_result = field_info[index]
            try:
                info_str = f"layer_name: {seed_result['layer_name']}, field_name: {seed_result['field_name']}, semantic: {seed_result['semantic']}, defined_values: {seed_result['defined_values']}"
                agent = create_agent(base_llm,k_value=30)
                query = get_prompt(info_str)
        #             # print(seed_result['mutation'])

                response = agent.invoke(query)
                print(response['output'].replace("```json\n", "").replace("```", ""))
                final_result = response['output'].replace("```json\n", "").replace("```", "")
                # 将字符串解析为字典
                final_result_dict = json.loads(final_result)
                # 创建新的有序字典，将info_str放在最前面
                ordered_dict = {"info_str": info_str}
                # 添加其他字段
                ordered_dict.update(final_result_dict)
                # 将字典转换回JSON字符串，使用indent参数确保格式化输出
                final_result = json.dumps(ordered_dict, indent=2, ensure_ascii=False)
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
                        write_result(final_result)
                        index += 1
                        print(f"完成第{index}个种子")
                except Exception as e:
                #写一个空json
                    final_result = json.dumps({"log_id":index, "error":str(e)})
                    write_result(final_result)
                    print(f"第{index}个种子出错")
            
if __name__ == "__main__":
    main()