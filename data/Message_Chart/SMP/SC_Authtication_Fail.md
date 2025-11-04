```mermaid
sequenceDiagram
    participant Master
    participant Slave

    Slave-->>Master: Pairing Confirm 
    Master->>Slave: Pairing Random 
    Slave-->>Master: Pairing Random
    Master->>Slave: Pairing Failed
