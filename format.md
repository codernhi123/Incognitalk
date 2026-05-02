# E2EE Chat Protocol Specification (v1.0)

## Global Framing Rule (TLV)
Every single packet transmitted over the TCP stream MUST begin with a 3-byte header:
- `[Type]` (1 byte): Defines the purpose of the packet.
- `[Length]` (2 bytes, Unsigned Big-Endian): Defines the exact byte size of the `[Payload]`. 
  *(Note: Length does NOT include the 3-byte header itself).*

---

## TYPE 0: JOIN (Client joining a room)

**Client -> Server** (Request to join)
- **Header:** `<Type 0> <Length>`
- **Payload:** `<Group ID (4 bytes)> <Public Key (Variable)>`
- *Note:* The client does not send IP/Port. The server implicitly knows their network identity.

**Server -> Initiator/Host Client** (Notification of newcomer)
- **Header:** `<Type 0> <Length>`
- **Payload:** `<Newcomer Client ID (2 bytes)> <Newcomer Public Key (Variable)>`
- *Note:* The server assigns a temporary Client ID and passes it to the host so the host knows who to encrypt the symmetric key for.

---

## TYPE 1: CHAT (Normal Encrypted Messaging)

**Client -> Server** (Sending a message)
- **Header:** `<Type 1> <Length>`
- **Payload:** `<IV (16 bytes)> <Encrypted Ciphertext (Variable)>`
- *Note:* The `Length` now equals 16 + length of ciphertext.

**Server -> Other Clients** (Broadcasting the message)
- **Header:** `<Type 1> <Length>`
- **Payload:** `<Sender Client ID (2 bytes)> <IV (16 bytes)> <Encrypted Ciphertext (Variable)>`

---

## TYPE 2: KEY EXCHANGE (Distributing the Symmetric Key)

**Initiator Client -> Server** (Sending the key to the newcomer)
- **Header:** `<Type 2> <Length>`
- **Payload:** `<Target Client ID (2 bytes)> <Encrypted Symmetric Key (Variable)>`
- *Note:* The encrypted key is encrypted using the newcomer's public key.

**Server -> Newcomer Client** (Delivering the key)
- **Header:** `<Type 2> <Length>`
- **Payload:** `<Encrypted Symmetric Key (Variable)>`
- *Note:* The server strips the Target ID and routes the ciphertext exclusively to the exact socket matching that Target ID.

---

## TYPE 3: LEAVE (Graceful Disconnect)

**Client -> Server** (Intent to leave)
- **Header:** `<Type 3> <Length: 0>`
- **Payload:** `[Empty]`
- *Note:* The server receives this, removes the client from the room struct, and calls `close()`.

**Server -> Other Clients** (Notification of departure)
- **Header:** `<Type 3> <Length: 2>`
- **Payload:** `<Leaving Client ID (2 bytes)>`
- *Note:* Allows the UI to print "User [ID] has left the chat."

---

## TYPE 4: HOST INITIALIZATION (Creating a room)

**Host Client -> Server** (Request to create the room)
- **Header:** `<Type 4> <Length: 4>`
- **Payload:** `<Group ID (4 bytes)>`
- *Note:* The host sends this immediately upon connection (`STATE_JUST_CONNECTED`). The server uses this 4-byte payload to instantiate the `GroupChat_Metadata` struct and register this socket as the room's Host.

**Server -> Host Client** (No Response)
- *Note:* The server does not send a confirmation message. It simply creates the room and waits for non-host clients to send Type 0 messages.