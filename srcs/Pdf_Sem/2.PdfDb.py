import os
from pydoc import doc
import sys
import json
import re
from tkinter import N

from openai import embeddings
sys.path.insert(0,os.path.dirname(os.path.dirname(os.path.abspath(__file__)))+"/../../")
from click import prompt

from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain_openai import OpenAIEmbeddings

from langchain_community.vectorstores import FAISS
from langchain.schema import Document

from BSFuzz.srcs.Log_Config.logger_config import *
from BSFuzz.srcs.Config_File.Cypress import config
from pdf2image import convert_from_path

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

# def load_txt(txt_path, chunk_size=1000000):
#     """
#     加载TXT文件并按块分割
#     Args:
#         txt_path: TXT文件路径
#         chunk_size: 每块的字符数，默认1000
#     Returns:
#         包含文本块的Document列表
#     """
#     print(f"开始读取 TXT 文件: {txt_path}")
#     doc = []
    
#     try:
#         with open(txt_path, 'r', encoding='utf-8') as file:
#             # 读取整个文件并预处理
#             text = file.read()
#             text = clean_text(text)  # 在分块之前先清理整个文本

            
#         # 按chunk_size分割文本
#         chunks = [text[i:i + chunk_size] for i in range(0, len(text), chunk_size)]
#         print(len(chunks))
        
#         # 为每个文本块创建Document对象
#         for i, chunk in enumerate(chunks):
#             # 跳过空白块
#             if not chunk.strip():
#                 continue
#             # 创建Document对象，包含块号信息
#             chunk_doc = Document(
#                 page_content=chunk.strip(),
#                 metadata={
#                     "chunk": i + 1,
#                     "start_char": i * chunk_size,
#                     "end_char": min((i + 1) * chunk_size, len(text))
#                 }
#             )
#             doc.append(chunk_doc)
            
#         print(f"成功加载文件，共分割为 {len(doc)} 个文本块")
#         return doc
        
    # except Exception as e:
    #     print(f"读取文件时出错: {str(e)}")
    #     return []

def chunk_text(text: str, chunk_size=1000, chunk_overlap=200, separator="."):
    """
    直接对清理后的文本进行分割
    Args:
        text: 清理后的文本字符串
        chunk_size: 每个块的大小
        chunk_overlap: 块之间的重叠大小
        separator: 分隔符
    Returns:
        包含文本块的Document列表
    """
    # print(text) 
    text_splitter = RecursiveCharacterTextSplitter(chunk_size=chunk_size, chunk_overlap=chunk_overlap,separators=[".",])
    
    # 直接分割文本
    text_chunks = text_splitter.split_text(text)

    # 将文本块转换为Document对象
    chunks = []
    for i, chunk in enumerate(text_chunks):
        if chunk.strip():  # 跳过空白块
            doc = Document(
                page_content=chunk.strip(),
                metadata={
                    "chunk": i + 1,
                    "start_char": i * chunk_size,
                    "end_char": min((i + 1) * chunk_size, len(text))
                }
            )
            chunks.append(doc)
    
    print(f"生成 {len(chunks)} 个 Chunk，每个 Chunk 大小: {chunk_size}")
    return chunks

def save_to_faiss(chunks, faiss_index_path):
    embeddings = OpenAIEmbeddings(model=embedding_model)  # 你可以换成 SentenceTransformer
    print("received embeddings")
    vectorstore = FAISS.from_documents(chunks, embeddings)
    vectorstore.save_local(faiss_index_path)  # 保存到本地

    vectorstore.save_local(faiss_index_path)  # 保存到本地
    print(f"向量数据库已保存到 {faiss_index_path}")
    return vectorstore


def load_documents(txt_path):
    with open(txt_path, 'r', encoding='utf-8') as file:
        text = file.read()
    cleaned_text = clean_text(text)
    chunks = chunk_text(cleaned_text)
    return chunks

if __name__ == "__main__":
    # 读取并清理文本
    with open(txt_path, 'r', encoding='utf-8') as file:
        text = file.read()
    cleaned_text = clean_text(text)

    # 直接对清理后的文本进行分块
    chunks = chunk_text(cleaned_text)
    # print(chunks)
    Faiss = save_to_faiss(chunks,faiss_index_path)

