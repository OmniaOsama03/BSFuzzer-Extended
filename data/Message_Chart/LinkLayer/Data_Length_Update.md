```mermaid

sequenceDiagram
    participant Client
    participant Peripheral 

    Client->>Peripheral: LL_LENGTH_REQ
    Peripheral-->>Client: LL_LENGTH_RSP