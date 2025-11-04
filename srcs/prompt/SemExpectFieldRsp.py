from langchain_core.prompts import PromptTemplate

SemRspPrompt = PromptTemplate(
            input_variables=["field_info"],
            template="""
You are a Bluetooth Core Specification certified expert. Analyze the expected device behavior when receiving a packet with invalid or unsupported field values, CRC check correct. following the structure below:
{field_info}

Analysis Requirements

1. Violation Scenarios 
   Protocol-Level Violation: Directly violates the defined value range or format
   Capability Mismatch: Technically valid, but exceeds receiver's implementation limits 

2. Behavior Prediction
   Mandatory Behavior: Required behavior per the spec
   Recommended Behavior: Optional implementation behavior
   Error Signaling: Silent drop / Send `[ERROR_CODE]` / Return `[SPECIFIC_REJECT_PACKET]`, prioritization of error codes 


---

### **Output Template**
Json format:
```
{{
  "ProtocolComplianceCheck": {{
    "SpecReference": "Vol X Part Y §Z",
    "Verdict": "Valid / Invalid + violated clause"
  }},
  "ExpectedDeviceBehavior": {{
    "PrimaryAction": "Drop / Error Response / Normal Processing...",
    "ErrorResponseType": "Packet Type + Error Code",
  
  }}
}}

---

### **Example Analysis** *(Using LL\_LENGTH\_REQ as example)*:

{{
  "ProtocolComplianceCheck": {{
    "SpecReference": "Vol 6 Part B §4.5.10",
    "Verdict": "Invalid — violates minimum value of 27 octets for max_rx_bytes"
  }},
  "ExpectedDeviceBehavior": {{
    "PrimaryAction": "Error Response",
    "ErrorResponseType": "LL_REJECT_EXT_IND (Error Code: 0x12)",
  
  }}
}}

        """
    )

def get_prompt(field_info):
    return SemRspPrompt.format(field_info=field_info)

if __name__ == "__main__":
    print(get_prompt(field_info="layer_name: LL_LENGTH_REQ, field_name: max_rx_bytes, semantic: Specifies the maximum number of octets that the sender can receive, ensuring that the sender does not announce a capability lower than 27 octets., defined_values: 0x001B-0xFFFF (Minimum value 27 octets, no maximum defined)"))




