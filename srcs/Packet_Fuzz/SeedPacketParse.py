import json

class SeedPacketParser:
    def __init__(self, json_file_path):
        self.json_file_path = json_file_path
        self.data = self._load_json()
        
    def _load_json(self):
        """加载JSON文件"""
        try:
            with open(self.json_file_path, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"读取JSON文件失败: {str(e)}")
            return None
            
    def get_all_packet_names(self):
        """获取所有数据包名称"""
        if not self.data:
            return []
        return [packet["name"] for packet in self.data.get("packets", [])]
        
    def get_packet_fields(self, packet_name):
        """获取指定数据包的所有字段"""
        if not self.data:
            return []
        for packet in self.data.get("packets", []):
            if packet["name"] == packet_name:
                return [field["name"] for field in packet.get("fields", [])]
        return []
        
    def get_field_mutations(self, packet_name, field_name):
        """获取指定字段的所有变异测试用例"""
        if not self.data:
            return []
        for packet in self.data.get("packets", []):
            if packet["name"] == packet_name:
                for field in packet.get("fields", []):
                    if field["name"] == field_name:
                        mutations = []
                        for mutation in field.get("mutations", []):
                            mutations.extend(mutation.get("TestCases", []))
                        return mutations
        return []
        
    def get_field_dependency_mutations(self, packet_name, field_name):
        """获取指定字段的依赖变异测试用例"""
        if not self.data:
            return []
        for packet in self.data.get("packets", []):
            if packet["name"] == packet_name:
                for field in packet.get("fields", []):
                    if field["name"] == field_name:
                        for mutation in field.get("mutations", []):
                            if mutation["MutationType"] == "Field Dependency Mutation":
                                return mutation.get("TestCases", [])
        return []



if __name__ == "__main__":
    parser = SeedPacketParser("/home/yangting/Documents/Semantic/data/sem_seed/semseed.json")
    
    # 获取所有数据包名称
    packet_names = parser.get_all_packet_names()
    print("数据包名称列表:")
    for name in packet_names:
        print(f"- {name}")
        
    # 获取特定数据包的字段
    packet_name = "SM_Pairing_Request"
    fields = parser.get_packet_fields(packet_name)
    print(f"\n{packet_name} 的字段:")
    for field in fields:
        print(f"- {field}")
        
    # 获取特定字段的变异测试用例
    field_name = "iocap"
    mutations = parser.get_field_mutations(packet_name, field_name)
    print(f"\n{packet_name}.{field_name} 的变异测试用例:")
    for mutation in mutations:
        print(f"- 值: {mutation.get(field_name)}, 测试类型: {mutation.get('TestType')}")
        
    # 获取特定字段的依赖变异测试用例
    dependency_mutations = parser.get_field_dependency_mutations(packet_name, field_name)
    print(f"\n{packet_name}.{field_name} 的依赖变异测试用例:")
   
    items = list(dependency_mutations[0].items()) 
    
    # for mutation in items:
      
        # print(f"- 值: {mutation[0]}, 数据包: {mutation[1]}, "
        #       f"测试类型: {mutation[2]}")
