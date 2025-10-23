import xml.etree.ElementTree as ET
from scapy.all import Packet


class PacketDescriptionGenerator:
    def __init__(self, xml_path):
        """Initialize SMP packet description generator"""
        self.tree = ET.parse(xml_path)
        self.root = self.tree.getroot()

    def get_packet_description(self, packet_name):
        """Get complete description for a specified packet
        
        Args:
            packet_name: Name of the packet to describe
            
        Returns:
            A formatted string containing the packet description
        """
        # Find the specified packet
        packets = self.root.findall(f".//packet[@name='{packet_name}']")
        if packets is None:
            return f"Packet not found: {packet_name}"

        description = []
        description.append(f"Packet Name: {packet_name}")
        description.append("=" * 2)
        description.append(f"Number of Fields: {len(packets)}")

        # Get all fields information
        for packet in packets:
            field = packet.find(".//field")
            field_name = field.get("name")
            field_desc = []
            field_desc.append(f"\nField Name: {field_name}")
            field_bit_length = field.find("field_bit_length")
            if field_bit_length is not None and field_bit_length.text:
                field_desc.append(f"Field Bit Length: {field_bit_length.text}")

            # Get semantic description
            semantic = field.find("semantic")
            if semantic is not None and semantic.text:
                field_desc.append(f"Semantic Description: {semantic.text}")

            # Get defined values
            defined_values = field.find("defined_values")
            if defined_values is not None and defined_values.text:
                field_desc.append(f"Defined Values: {defined_values.text}")

            description.append("\n".join(field_desc))
            description.append("-" * 2)

        return "\n".join(description)
    
    def get_all_packet_description(self,pkt:Packet):
        """获取所有数据包的描述信息"""
        
        # Args:
        #     packet_name: 数据包名称
        # 遍历packet的每个layer
        description = []
        while pkt.payload:
            for field in pkt.payload.fields_desc:
                description.append(f"Field Name: {field.name}")
                description.append(f"Field Description: {self.get_field_description(type(pkt.payload).__name__,field.name)}")
                description.append("------" * 2)
            pkt = pkt.payload
        return "\n".join(description)

    def get_field_bit_length(self, packet_name, target_field):
        """获取特定字段的位长度"""
        packets = self.root.findall(f".//packet[@name='{packet_name}']")
        if not packets:
            return f"Packet not found: {packet_name}"
        for packet in packets:
            fields = packet.findall(".//field")
            for field in fields:
                field_name = field.get("name")
                if field_name == target_field:
                    field_bit_length = field.find("field_bit_length")
                    if field_bit_length is not None and field_bit_length.text:
                        return field_bit_length.text
        return f"Field {target_field} not found in packet {packet_name}"
        

    def get_field_description(self, packet_name, target_field):
        """获取特定字段的描述信息
        
        Args:
            packet_name: 数据包名称
            target_field: 目标字段名称
            
        Returns:
            字段描述的字符串
        """
        packets = self.root.findall(f".//packet[@name='{packet_name}']")
        if not packets:
            return f"Packet not found: {packet_name}"

        description = []
        description.append(f"Packet Name: {packet_name}")
    

        for packet in packets:
            fields = packet.findall(".//field")
            for field in fields:
                field_name = field.get("name")
                if field_name == target_field:
                    field_desc = []
                    field_desc.append(f"Field Name: {field_name}")
                    
                    field_bit_length = field.find("field_bit_length")
                    if field_bit_length is not None and field_bit_length.text:
                        field_desc.append(f"Field Bit Length: {field_bit_length.text}")

                    semantic = field.find("semantic")
                    if semantic is not None and semantic.text:
                        field_desc.append(f"Semantic Description: {semantic.text}")

                    defined_values = field.find("defined_values")
                    if defined_values is not None and defined_values.text:
                        field_desc.append(f"Defined Values: {defined_values.text}")

                    description.append("\n".join(field_desc))
                    return "\n".join(description)

        return f"Field {target_field} not found in packet {packet_name}"

    def extract_packet_fields(self):
        """提取所有数据包及其字段
        
        Returns:
            一个列表，每个元素是一个字典，包含 "packet name" 和 "field" 键
        """
        # 存储结果的列表
        result = []
        
        # 遍历所有packet元素
        for packet in self.root.findall('.//packet'):
            packet_name = packet.get('name')
            
            # 遍历packet下的所有field元素
            for field in packet.findall('./field'):
                field_name = field.get('name')
                
                # 将数据包名称和字段名称添加到结果列表中
                result.append({
                    "packet name": packet_name,
                    "field": field_name
                })
        
        return result
    def get_packet_fields(self,packet_name):
        # 获取一个数据包的fields,先找到所有名称相同的数据包，然后获取所有field
        packets = self.root.findall(f".//packet[@name='{packet_name}']")
        if packets is None:
            return f"Packet not found: {packet_name}"
        fields = []
        for packet in packets:
            fields.extend(packet.findall(".//field"))
        return ",".join([field.get("name") for field in fields])

# def main():
#     # XML file path
#     xml_path = "/home/yangting/Documents/Semantic/data/sem_seed/smp_layer.xml"  # Replace with actual smp_layer.xml path
    
#     # Create generator instance
#     generator = SMPPacketDescriptionGenerator(xml_path)
    
#     # Generate descriptions for all packets
#     # generator.get_packet_description("SM_Pairing_Request")

#     # Or generate description for a specific packet
#     packet_name = "SM_Pairing_Request"
#     description = generator.get_packet_description(packet_name)
#     print(description)


# if __name__ == "__main__":
#     generator = PacketDescriptionGenerator("/home/yangting/Documents/Semantic/data/sem_seed/merged.xml")
#     # 提取数据包字段
#     packet_fields = generator.get_packet_fields(packet_name="BTLE_DATA")
#     print(packet_fields)
    # Generate descriptions for all packets
    # generator.get_packet_description("SM_Pairing_Request")