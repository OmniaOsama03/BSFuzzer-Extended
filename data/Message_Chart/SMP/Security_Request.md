```mermaid
sequenceDiagram
    participant Master
    participant Slave

    Slave->>Master: Security Request 
    Master->>Slave: Pairing Request
    Slave-->>Master: Pairing Response

