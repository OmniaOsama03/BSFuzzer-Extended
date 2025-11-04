import os

import sys
import json
import re

sys.path.insert(0,os.path.dirname(os.path.dirname(os.path.abspath(__file__)))+"/../../")
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain_openai import OpenAIEmbeddings

from langchain_community.vectorstores import FAISS
from langchain.schema import Document
from BSFuzz.srcs.Log_Config.logger_config import *
from BSFuzz.srcs.Config_File.Esp32 import config
from BSFuzz.srcs.llm_model.ModConf import ModelConfig


with open("/home/yangting/Documents/Semantic/config/semext_config.json", "r") as file:
    config = json.load(file)
    model_config = ModelConfig(config.get("llm", {}).get("model_provider"))
    model = config.get("llm", {}).get("model")
    model_config.update_config({"model":config.get("llm", {}).get("model"),"temperature":config.get("llm", {}).get("temperature"),"max_tokens":config.get("llm", {}).get("max_tokens")})
    llm = model_config.get_llm()
    txt_path = config.get("semext_mesh", {}).get("txt_path")
    faiss_index_path = config.get("semext_mesh", {}).get("faiss_index_path")
    index_name = txt_path.split('/')[-1].split('.')[0]
    xml_path = config.get("semext_mesh", {}).get("xml_file_path")
    embedding_model = config.get("llm", {}).get("embedding_model")

def clean_text(text):
    """
    清理文本中的特定内容
    """
    # 清理规则
    patterns = [
        r'Bluetooth SIG Proprietary',
        r'BLUETOOTH SPECIFICATION Version[\s\S]*?(?=\n)',
        r'\d{2}\s+(?:January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{4}',
        r'Bluetooth®',
        r'page\s+\d+',
        r'\.{3,}',  # 匹配3个或更多的英文点（省略号）
        r'…+',      # 匹配1个或多个中文省略号
    ]
    
    cleaned_text = text
    for pattern in patterns:
        cleaned_text = re.sub(pattern, '', cleaned_text)
    
    # 删除换行符和多余的空白字符
    cleaned_text = re.sub(r'(\w+)-\s+(\w+)', lambda m: m.group(1) + m.group(2), cleaned_text)
    cleaned_text = re.sub(r'\n+', ' ', cleaned_text)  # 将换行符替换为空格
    cleaned_text = re.sub(r'\s+', ' ', cleaned_text)  # 将多个空白字符替换为单个空格
    return cleaned_text.strip()


def chunk_text(text: str, chunk_size=1000, chunk_overlap=200, separator="."):
    # print(text) 
    text_splitter = RecursiveCharacterTextSplitter(chunk_size=chunk_size, chunk_overlap=chunk_overlap,separators=[".",])
    

    text_chunks = text_splitter.split_text(text)

    chunks = []
    for i, chunk in enumerate(text_chunks):
        if chunk.strip():  
            doc = Document(
                page_content=chunk.strip(),
                metadata={
                    "chunk": i + 1,
                    "start_char": i * chunk_size,
                    "end_char": min((i + 1) * chunk_size, len(text))
                }
            )
            chunks.append(doc)
    
    print(f"Generated {len(chunks)} chunks, each chunk size: {chunk_size}")
    return chunks

def save_to_faiss(chunks, faiss_index_path):
    embeddings = OpenAIEmbeddings(model=embedding_model) 
    print("received embeddings")
    vectorstore = FAISS.from_documents(chunks, embeddings)
    vectorstore.save_local(faiss_index_path)  

    vectorstore.save_local(faiss_index_path) 
    print(f"Vector database saved to {faiss_index_path}")
    return vectorstore


if __name__ == "__main__":

    with open(txt_path, 'r', encoding='utf-8') as file:
        text = file.read()
    cleaned_text = clean_text(text)
    chunks = chunk_text(cleaned_text)

    Faiss = save_to_faiss(chunks,faiss_index_path)

