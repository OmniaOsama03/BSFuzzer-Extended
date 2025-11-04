```mermaid
sequenceDiagram
    participant Master
    participant Slave


    Slave-->>Master: Encryption Information (Long Term Key)
    Slave-->>Master: Master Identification (EDIV, Rand)
    Slave-->>Master: Identity Information (Identity Resolving Key)
    Slave-->>Master: Identity Address Information (AddrType, BD_ADDR)
    Slave-->>Master: Signing Information (Signature Key)

    Master->>Slave: Encryption Information (Long Term Key)
    Master->>Slave: Master Identification (EDIV, Rand)
    Master->>Slave: Identity Information (Identity Resolving Key)
    Master->>Slave: Identity Address Information (AddrType, BD_ADDR)
    Master->>Slave: Signing Information (Signature Key)
