
```mermaid
sequenceDiagram
    participant Client
    participant Peripheral

    Client->>Peripheral: LL_ENC_REQ
    Peripheral-->>Client: LL_ENC_RSP
    Peripheral-->>Client: LL_START_ENC_REQ
    Client->>Peripheral: LL_START_ENC_RSP
    Peripheral-->>Client: LL_START_ENC_RSP 
