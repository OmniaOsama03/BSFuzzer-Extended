import os
from PyPDF2 import PdfReader, PdfWriter
from google.api_core.client_options import ClientOptions
# from google.cloud.documentai_toolbox import document
from google.cloud import documentai
import math
import shutil
import re



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

def document_to_clean_text(document):

    md_content = []

    # 提取文档中的文本内容
    if document.text:
        # 清理文本
        cleaned_text = clean_text(document.text)
       
        paragraphs = cleaned_text.split('. ')
        for paragraph in paragraphs:
            if paragraph.strip():
                md_content.append(paragraph.strip() + '.\n')

    # 提取文档中的表格
    for page in document.pages:
        for table in page.tables:
            md_content.append('\n') # 表格前添加空行
            # 处理表头
            headers = []
            if table.header_rows:
                for header_cell in table.header_rows[0].cells:
                    cell_text = clean_text(header_cell.layout.text)
                    headers.append(cell_text)
                if headers:
                    md_content.append("| " + " | ".join(headers) + " |")
                    md_content.append("|" + " --- |" * len(headers))

            # 处理表格内容
            for row in table.body_rows:
                cells = []
                for cell in row.cells:
                    cell_text = clean_text(cell.layout.text)
                    cells.append(cell_text)
                if cells:
                    md_content.append("| " + " | ".join(cells) + " |")
            md_content.append('\n') # 表格后添加空行

    return "\n".join(md_content)

def split_and_process_pdf(
    project_id: str,
    location: str,
    input_pdf_path: str,
    output_txt_path: str,  # 改为markdown输出路径
    pages_per_chunk: int,
    process_id: str,
):
    """
    分割并处理PDF文件，输出为Markdown格式
    """
    # 创建输出目录
    temp_dir = "temp_pdf_chunks"
    os.makedirs(temp_dir, exist_ok=True)
    os.makedirs(os.path.dirname(output_txt_path), exist_ok=True)
    
    # 读取PDF文件
    pdf = PdfReader(input_pdf_path)
    total_pages = len(pdf.pages)
    chunks = math.ceil(total_pages / pages_per_chunk)
    
    # 设置Document AI客户端
    client = documentai.DocumentProcessorServiceClient(
        client_options=ClientOptions(api_endpoint=f"{location}-documentai.googleapis.com")
    )
    
    processor_name = f"projects/{project_id}/locations/{location}/processors/{process_id}"
    
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
            
            # 创建新的PDF写入器
            pdf_writer = PdfWriter()
            
            # 添加页面到新的PDF
            for page_num in range(start_page, end_page):
                pdf_writer.add_page(pdf.pages[page_num])
            
            # 保存临时PDF文件
            temp_pdf_path = os.path.join(temp_dir, f"chunk_{i+1}.pdf")
            with open(temp_pdf_path, "wb") as temp_pdf:
                pdf_writer.write(temp_pdf)
            
            print(f"Processing PDF chunk {i+1}/{chunks}...")
            
            try:
                # 读取临时PDF文件并处理
                with open(temp_pdf_path, "rb") as pdf_file:
                    pdf_content = pdf_file.read()
                
                # 配置处理请求
                raw_document = documentai.RawDocument(
                    content=pdf_content,
                    mime_type="application/pdf",
                )
                request = documentai.ProcessRequest(
                    name=processor_name,
                    raw_document=raw_document
                )
                
                # 处理文档
                result = client.process_document(request=request)
                document = result.document
                
                # 转换为Markdown并添加到列表
                markdown_text = document_to_clean_text(document)
                all_markdown.append(markdown_text)
                
            except Exception as e:
                print(f"Error processing chunk {i+1}: {str(e)}")
                continue
            finally:
                # 删除临时PDF文件
                if os.path.exists(temp_pdf_path):
                    os.remove(temp_pdf_path)
        
        # 将所有markdown内容写入输出文件
        if all_markdown:
            with open(output_txt_path, "w", encoding="utf-8") as md_file:
                md_file.write("\n".join(all_markdown))
            print(f"Markdown file saved to: {output_txt_path}")
        else:
            print("Warning: No content extracted")
        
    finally:
        # 清理临时目录
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)

if __name__ == "__main__":
    # 配置参数
    project_id = "10x031x0914x8"
    location = "us"
    input_pdf_path = "path/to/your/file.pdf"
    output_txt_path = "path/to/output/file.txt"  # 改为.txt后缀
    pages_per_chunk = 15
    process_id = "93338v5b34543r7d"
    
    # 执行处理
    split_and_process_pdf(
        project_id=project_id,
        location=location,
        input_pdf_path=input_pdf_path,
        output_txt_path=output_txt_path,  # 使用新的参数名
        pages_per_chunk=pages_per_chunk,
        process_id=process_id
    )
