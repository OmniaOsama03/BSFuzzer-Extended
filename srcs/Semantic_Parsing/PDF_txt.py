import os
from PyPDF2 import PdfReader, PdfWriter
#from google.api_core.client_options import ClientOptions
# from google.cloud.documentai_toolbox import document
#from google.cloud import documentai
import math
import shutil
import re

#New import for local pymupdf
import pymupdf
from pathlib import Path




def clean_text(text):
    """
    清理文本中的特定内容
    """
   
    patterns = [
        r'Bluetooth SIG Proprietary',
        r'BLUETOOTH SPECIFICATION Version[\s\S]*?(?=\n)',
        r'\d{2}\s+(?:January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{4}',
        r'Bluetooth®',
        r'page\s+\d+',
        r'\.{3,}', 
        r'…+',      
    ]
    
    cleaned_text = text
    for pattern in patterns:
        cleaned_text = re.sub(pattern, '', cleaned_text)
    
    # 处理断字（例如：cal- culated -> calculated）
    cleaned_text = re.sub(r'(\w+)-\s+(\w+)', lambda m: m.group(1) + m.group(2), cleaned_text)
    
    # 删除换行符和多余的空白字符
    cleaned_text = re.sub(r'\n+', ' ', cleaned_text)  # 将换行符替换为空格
    cleaned_text = re.sub(r'\s+', ' ', cleaned_text)  # 将多个空白字符替换为单个空格
    return cleaned_text.strip()

def document_to_clean_text(text):
    return clean_text(text)
    

def split_and_process_pdf(
    input_pdf_path: str,
    output_txt_path: str,  # 改为markdown输出路径
    pages_per_chunk: int,
):
    """
    分割并处理PDF文件，输出为Markdown格式
    #Extracting PDF text using PyMyPDF
    """
    # 创建输出目录
    os.makedirs(os.path.dirname(output_txt_path), exist_ok=True)
    
    # PyMuPDF implementation
    pdf = pymupdf.open(input_pdf_path)
    total_pages = len(pdf)
    chunks = math.ceil(total_pages + pages_per_chunk -1) // pages_per_chunk
    
    
    # 用于存储所有markdown内容
    all_markdown = []
    
    try:
        # 添加文档标题
        pdf_name = os.path.splitext(os.path.basename(input_pdf_path))[0]
        all_markdown.append(f"# {pdf_name}\n\n")
        
        # 分割PDF并处理每个部分
        for i in range(chunks):
            start_page = i * pages_per_chunk
            end_page = min((i + 1) * pages_per_chunk, total_pages)
            
            print(f"Processing PDF chunk {i+1}/{chunks}...")
            
            try:
                # 读取临时PDF文件并处理
                #Extract text from each page in this chunk
                chunk_text = []
                
                for page_num in range(start_page,end_page):
                    page = pdf[page_num]
                    page_text = page.get_text("text", sort = True)
                    chunk_text.append(page_text)
                    
                #Convert extracted text to cleaned Markdown
                markdown_text = document_to_clean_text("\n".join(chunk_text))
                
                # 转换为Markdown并添加到列表
                all_markdown.append(markdown_text)
                
            except Exception as e:
                print(f"Error processing chunk {i+1}: {str(e)}")
                continue
        
        # 将所有markdown内容写入输出文件 OUTPUT 
        if all_markdown:
            with open(output_txt_path, "w", encoding="utf-8") as md_file:
                md_file.write("\n".join(all_markdown))
            print(f"Markdown file saved to: {output_txt_path}")
        else:
            print("Warning: No content extracted")
        
    finally:
        pdf.close()

if __name__ == "__main__":
    # 配置参数
    input_pdf_path = "/home/silver/BSFuzzer-Extended/data/Core_v5.0_ATT.pdf"
    output_txt_path = "/home/silver/BSFuzzer-Extended/data/V5.0/ATT.txt"  # 改为.txt后缀
    pages_per_chunk = 15
    
    # 执行处理
    split_and_process_pdf(
        input_pdf_path=input_pdf_path,
        output_txt_path=output_txt_path,  # 使用新的参数名
        pages_per_chunk=pages_per_chunk,
    )
