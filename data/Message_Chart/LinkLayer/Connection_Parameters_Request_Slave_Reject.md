```mermaid
sequenceDiagram
    participant Client
    participant Peripheral

 
    Peripheral-->>Client: LL_CONNECTION_PARAM_REQ
    Client->>Peripheral: LL_REJECT_EXT_IND
