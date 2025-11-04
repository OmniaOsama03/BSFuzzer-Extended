```mermaid
sequenceDiagram
    participant Client
    participant Peripheral

    Client->>Peripheral: LL_PHY_REQ
    Peripheral-->>Client: LL_UNKNOWN_RSP
  
