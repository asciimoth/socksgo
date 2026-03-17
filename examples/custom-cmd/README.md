# Custom HelloWorld Command Example

This example demonstrates how to create a custom SOCKS command with client-server implementation.

## Overview

The example shows:
- Server side: Custom handler for a `0xF4` command that responds with "Hello, World!"
- Client side: Uses `Client.Request()` to send the custom command to the server

## Running the Example

Start the server:

```bash
go run ./server
```

The server will listen on `127.0.0.1:1080` by default.

Run the client in a separate terminal:

```bash
go run ./client
```

The client will connect to the server and send the custom HelloWorld command with a payload.

### Custom Options

**Server:**
- `-addr`: Listen address (default: `127.0.0.1:1080`)

**Client:**
- `-proxy`: SOCKS proxy URL (default: `socks5://127.0.0.1:1080`)
- `-payload`: Message to send with the command (default: `custom message`)

Example with custom payload:
```bash
go run ./client -payload "my custom message"
```

## How It Works

### Server Side

1. Define a custom command constant: `const CmdHelloWorld protocol.Cmd = 0xF4`
2. Create a `CommandHandler` that implements the custom logic
3. Register the handler in the server's `Handlers` map
4. The handler sends a success reply and writes "Hello, World!" to the connection

### Client Side

1. Create a SOCKS5 client from URL
2. Create an `Addr` containing the payload
3. Call `client.Request(ctx, CmdHelloWorld, addr)`
4. Read the response from the returned connection

