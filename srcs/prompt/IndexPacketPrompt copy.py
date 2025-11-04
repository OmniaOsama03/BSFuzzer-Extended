from langchain_core.prompts import PromptTemplate

question_template = PromptTemplate(
    input_variables=["packet_name","packet_name_2"],
    template = """
You are a bluetooth protocol expert, please analyze whether there is a direct dependency between the parameters of the {packet_name} and {packet_name_2}. Specifically:

Think about each field of the two data packets and then answer the question.
<output format>
{{
  "packet_name": "ll connection update ind",
  "packet_name_2": "ll terminate ind",
  "cross_packet_dependency": false,
  "explanation": {{
    "Connection Interval (LL Connection Update Ind) vs. Termination Reason (LL Terminate Ind)": "The Connection Interval in the LL Connection Update Ind packet specifies the time between connection events, which does not directly influence the Termination Reason in the LL Terminate Ind packet. The termination reason is determined by higher-layer logic or specific conditions unrelated to the connection interval.",
    "Peripheral Latency (LL Connection Update Ind) vs. Termination Reason (LL Terminate Ind)": "Peripheral Latency allows the peripheral to skip connection events, but this does not directly affect the Termination Reason in the LL Terminate Ind packet. The decision to terminate a connection is independent of the peripheral's latency settings.",
    "Supervision Timeout (LL Connection Update Ind) vs. Termination Reason (LL Terminate Ind)": "The Supervision Timeout defines the maximum time between connection events before a link is considered lost. While a timeout could lead to a termination, the specific Termination Reason in the LL Terminate Ind packet is not directly dependent on the Supervision Timeout value itself.",
    "Other Fields": "Other fields in the LL Connection Update Ind packet, such as the Minimum and Maximum Connection Event Length, do not have a direct dependency on any fields in the LL Terminate Ind packet. The termination of a connection is typically driven by higher-layer decisions or specific error conditions rather than connection update parameters."
  }}
}}
{{
  "packet_name": "ll feature request",
  "packet_name_2": "smp pairing request",
  "cross_packet_dependency": true,
  "explanation": {{
    "Feature Set (LL) Bit 5 vs. AuthReq (SMP) Bit 2": "The LL Feature Set's LE Secure Connections bit directly influences the SMP Pairing Request's ability to request LE Secure Connections. If the LL does not support it, the SMP cannot negotiate it, creating a direct dependency.",
    "Feature Set (LL) Bit 0 vs. Max Encryption Key Size (SMP)": "The LL's LE Encryption support is a prerequisite for the SMP to negotiate an encryption key size. While not a field-to-field mapping, the SMP's encryption process depends on this LL capability.",
    "Other Fields": "Fields like IO Capability, OOB Data Flag, and Key Distribution in SMP do not have direct dependencies on LL Feature Set bits, though they operate within the security framework enabled by LL features."
  }}
}}
</output format>

Return ONLY valid JSON format
"""

)

def get_question(packet_name,packet_name_2):
    return question_template.format(packet_name=packet_name,packet_name_2=packet_name_2)




