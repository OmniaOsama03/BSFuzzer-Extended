import os
import sys


sys.path.insert(0,os.path.dirname(os.path.dirname(os.path.abspath(__file__)))+"/../../")
from langchain.prompts import PromptTemplate



from langchain.prompts import PromptTemplate

# Define the template for fuzz testing
template = """
As a Bluetooth protocol testing expert, your task is to generate protocol mutation test cases as client role based on state dependencies,target packet is {Target}.  
Please follow the process below:  

<Target Data Packet> {Target} </Target Data Packet> 
<Dependent packets>
{dependency_info}
</Dependent packets>

<Client Role>ll_feature_req_pkt → ll_length_req_pkt → ll_version_ind_pkt → smp_pairing_request_pkt → smp_pairing_public_key_pkt → smp_pairing_random_pkt → smp_pairing_dhkey_check_pkt → ll_enc_req_pkt → ll_start_enc_rsp_pkt → ll_pause_enc_req_pkt </Client Role>

### Generation Rules:  
- Parse Dependent packets to get the state transition requirements related to {Target}. 
- Comprehensive coverage of {Target}-related protocol violations to ensure comprehensive testing
- Based on the state transition requirements, generate the packet transmission path, at least one of the following state dependencies must be violated:  
- Must include: {Target} packet
- Prestate Not Completed  
- Repeated Operations Not Following Protocol Specifications 
- Unexpected State Change 
- Combinations containing the above variants
- Each test case corresponds to a specific failure scenario
- Technical basis description (cite the protocol chapter or specification clause)

### Generation Steps:  

1. List violations of specific parts and descriptions related to {Target} in <Analysis> tags.
2. Generate the packet transmission path. 
3. Only focus on the {Target} related state transition mutation.
3. Confirm in the <Validation> tag whether each mutation directly violates protocol clauses. 
4. Describe the specific mutation steps in <Mutation Steps>, using only: - Send [data packet name] - Skip [data packet name].
5. Generate 10 test cases, no repeat.

### Example Format:  

```xml
<Packet name="{Target}">
<TestCase ScenarioType="Pairing Process Interruption"> 
<Analysis>  
Based on Protocol Specification
</Analysis>  

<MutationSteps>  
1. Send Pairing Request.  
2. Skip Pairing Confirm.  
3. Directly send Encryption Request.  
</MutationSteps>  

<Validation>  
Technical basis description
</Validation>  
</TestCase>  
</Packet>
```

Please generate a complete set of test cases following this format, covering all specified failure scenarios, only output the xml format, no other text.
                   
"""
SemExtPrompt = PromptTemplate(
    input_variables=["Target","dependency_info"],  # 定义模板中的变量
    template=template,  # 模板内容
)

# prompt = SemExtPrompt.format(packet_name="pairing request", field="io_cap")
# print(prompt)
def get_prompt(target: str,dependency_info: str) -> str:
    return SemExtPrompt.format(Target=target,dependency_info=dependency_info)

if __name__ == "__main__":
    print(get_prompt("smp_pairing_request_pkt","smp_pairing_request_pkt,smp_pairing_confirm_pkt,smp_security_request_pkt,smp_pairing_public_key_pkt,smp_pairing_dhkey_check_pkt"))

