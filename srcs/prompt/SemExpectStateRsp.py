from langchain.prompts import PromptTemplate
packet_type =  "Received by slave device"
SemRspPrompt = PromptTemplate(
            input_variables=["layer","packet_name"],
            template="""
            As a Bluetooth Core Specification certified expert, analyze the required preconditions for the specified packet within the protocol stack and predict the device's response behavior based on whether the state is valid or invalid. The output must strictly follow the structure below:
            {{
            "AnalysisFramework": {{
              "ProtocolScope": {{
                "Layers": ["LL","SMP"]
              }},
              "StateValidationLogic": {{
                "Preconditions": [
                  "Connection state (encrypted/unencrypted)",
                  "Pairing phase (Phase 1–3)",
                  "Role (slave)",
                  "Feature exchange completion state",
                  "Security mode: need pairing, need encryption,lesc encryption mode, just work authentication mode"
                ],
                "ErrorHierarchy": {{
                  "PriorityReference": "Vol 1 Part F §3.4.1 (Error code priority rules)",
                  "ConflictResolution": "Use the highest priority error code"
                }}
              }}
            }},
            "InputTemplate": {{
              "PacketContext": {{
                "Layer": "{layer}",
                "PacketType": "{packet_name}",
                "Direction": "Received by slave device"
              }}
            }},
            "OutputTemplate": {{
              "PreviousStateAnalysis": {{
                "RequiredState": {{
                  "ConnectionState": ["Unencrypted", "Connected"],
                  "PairingPhase": "Determine between which two packets this packet should be sent to the slave, considering the Bluetooth pairing and encryption process.",
                  "PreviousPacketName": "Infer the possible packet name of the previous state for the current packet",
                  "RoleConstraint": "Either",
                  "SecurityMode": "Mode 1"
                }},
                "StateValidity": "Boolean"
              }},
              "ExpectedBehavior": {{
                "StateValidResponse": {{
                  "PrimaryAction": "NextPacketType",
                  "ErrorHandling": {{
                    "ResponseType": "PacketType/None",
                    "ErrorCode": "0xXX (SIG-defined code)"
                  }}
                }},
                "StateInvalidResponse": {{
                  "MandatoryAction": "ErrorPacketType",
                  "ErrorCodeSelectionLogic": "Include specific referenced core_spec_reference (Such as Vol 3 Part H §3.5.1)"
                }}
              }},
              "SpecificationCompliance": {{
                "NormativeReferences": [
                  "Include specific referenced core_spec_reference (Such as Vol 3 Part H §3.5.1)",
                  "Include specific referenced core_spec_reference (Such as Vol 3 Part C §9.3.1)"
                ]
              }}  
            }}
            }}
        """
    )

def get_prompt(layer,packet_name):
    return SemRspPrompt.format(layer=layer,packet_name=packet_name)

if __name__ == "__main__":
    print(get_prompt(layer="ll",packet_name="ll_encryption_request"))




