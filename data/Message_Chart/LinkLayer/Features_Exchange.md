```mermaid
sequenceDiagram
    participant Client
    participant Peripheral 

    Client->>Peripheral: LL_FEATURE_REQ
    Peripheral-->>Client: LL_FEATURE_RSP  
