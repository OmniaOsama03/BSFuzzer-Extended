import xml.etree.ElementTree as ET
import json

class XMLMerger:
    def __init__(self, config_file):
        with open(config_file, "r") as file:
            config = json.load(file)
            self.smp_xml_path = config.get("semext_smp", {}).get("xml_file_path")
            self.ll_xml_path = config.get("semext_ll", {}).get("xml_file_path")
            self.output_path = config.get("semext_merge", {}).get("xml_file_path")

    def merge_xml(self):
        """合并两个XML文件"""
        # 创建新的根元素
        merged_root = ET.Element("protocol")
        merged_root.set("name", "merge")

        # 解析两个XML文件
        smp_tree = ET.parse(self.smp_xml_path)
        ll_tree = ET.parse(self.ll_xml_path)
        
        # 获取根元素
        smp_root = smp_tree.getroot()
        ll_root = ll_tree.getroot()

        # 复制所有数据包定义
        for packet in smp_root.findall(".//packet"):
            merged_root.append(packet)
        
        for packet in ll_root.findall(".//packet"):
            merged_root.append(packet)

        # 创建新的ElementTree并保存
        merged_tree = ET.ElementTree(merged_root)
        merged_tree.write(self.output_path, encoding="utf-8", xml_declaration=True)

    def validate_merge(self):
        """验证合并后的XML文件"""
        try:
            tree = ET.parse(self.output_path)
            root = tree.getroot()
            
            # 检查协议名称
            if root.get("name") != "merge":
                print("错误：协议名称不正确")
                return False
            
            # 检查是否包含所有数据包
            smp_tree = ET.parse(self.smp_xml_path)
            ll_tree = ET.parse(self.ll_xml_path)
            
            smp_packets = set(p.get("name") for p in smp_tree.findall(".//packet"))
            ll_packets = set(p.get("name") for p in ll_tree.findall(".//packet"))
            merged_packets = set(p.get("name") for p in root.findall(".//packet"))
            
            if not (smp_packets.union(ll_packets) == merged_packets):
                print("错误：合并后的数据包数量不正确")
                return False
                
            print("验证成功：XML文件合并正确")
            return True
            
        except Exception as e:
            print(f"验证失败：{str(e)}")
            return False

if __name__ == "__main__":
    merger = XMLMerger("/home/yangting/Documents/BSFuzz/config/semext_config.json")
    merger.merge_xml()
    merger.validate_merge()