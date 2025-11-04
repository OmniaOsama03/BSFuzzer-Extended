```mermaid
sequenceDiagram
    participant Client
    participant Peripheral

    
    Peripheral-->>Client: LL_PHY_REQ
    Client->>Peripheral: LL_PHY_UPDATE_IND
  
