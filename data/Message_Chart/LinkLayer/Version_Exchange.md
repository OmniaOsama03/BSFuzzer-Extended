```mermaid
sequenceDiagram
    participant Client
    participant Peripheral 

    Client->>Peripheral: LL_VERSION_IND
    Peripheral-->>Client: LL_VERSION_IND  