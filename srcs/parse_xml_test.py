import xml.etree.ElementTree as ET
from langchain.embeddings.openai import OpenAIEmbeddings
from langchain.vectorstores import FAISS

from regex import P

class SemanticParser:
    def __init__(self, xml_path):
        self.tree = ET.parse(xml_path)
        self.root = self.tree.getroot()



    def get_field_semantic(self, packet_name, field_name):
        """获取指定数据包字段的语义描述和种子值"""
        packet = self.root.findall(f".//packet[@name='{packet_name}']")
        semantic = None
        defined_values = None

        if packet is None:
            return None, None
        for p in packet:
            field = p.find(f".//field[@name='{field_name}']")
            if field is not None:
                semantic = field.find('semantic')
                defined_values = field.find('defined_values')
                break
        
        semantic_text = semantic.text if semantic is not None else None
        defined_values_text = defined_values.text if defined_values is not None else None

        
        return semantic_text, defined_values_text

    def get_packet_fields(self):
        field_info = []
        for packet in self.root.findall('.//packet'):
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



if __name__ == "__main__":
    parser = SemanticParser('/home/yangting/Documents/Semantic/data/sem_seed/merged.xml')
    # 获取所有packet name field name semantic
    print(parser.get_packet_fields())

# tree = ET.parse('/home/yangting/Documents/Semantic/data/link_layer.xml')
# root = tree.getroot()

# # 找到 packet name="Pairing Request" 的元素
# packet = root.find(".//packet[@name='Pairing Request']")

# if packet is not None:
#     # 找到 field name="IO Capability" 的元素
#     field = packet.find(".//field[@name='IO Capability']")
#     if field is not None:
#         # 获取 semantic 描述
#         semantic = field.find('semantic')
#         if semantic is not None:
#             print(f'Semantic Description: {semantic.text}')
#         else:
#             print('Semantic element not found')
#     else:
#         print('Field element not found')
# else:
#     print('Packet element not found')