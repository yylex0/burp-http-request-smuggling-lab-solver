# HTTP Request Smuggling Lab Solver

Burp Suite extension that automates PortSwigger HTTP request smuggling labs, including HTTP/2 request tunnelling, cache poisoning, and client-side desync exploitation.

## Features

- Automates selected PortSwigger Web Security Academy labs
- Supports HTTP/2 request tunnelling workflows
- Supports cache poisoning via HTTP/2 request tunnelling
- Supports client-side desync exploitation
- Built on the Burp Montoya API

## Supported Labs

- Bypassing access controls via HTTP/2 request tunnelling
- Web cache poisoning via HTTP/2 request tunnelling
- Client-side desync

## Requirements

- Burp Suite with Java extension support
- Java 21 or later
- Burp Suite JAR available locally for compilation

## Repository Layout

- `src/main/java/beauty/burp/Http2TunnelSolverExtension.java`
- `build.sh`
- `build/http2-tunnel-solver.jar`

## Build

If Burp is installed at the default Kali path:

```bash
chmod +x build.sh
./build.sh
```

If your Burp JAR is somewhere else:

```bash
./build.sh /path/to/burpsuite.jar
```

The compiled extension JAR is written to:

```bash
build/http2-tunnel-solver.jar
```

## Load in Burp

1. Open `Extensions`
2. Click `Add`
3. Select `Java` as the extension type
4. Choose `build/http2-tunnel-solver.jar`
5. Load the extension

## Usage

### From the UI

1. Open the `H2 Tunnel Solver` tab
2. Enter the target lab URL
3. Choose a mode:
   `Bypass Access Control`, `Cache Poisoning XSS`, or `Client-side Desync`
4. Click `Solve`

### From the Context Menu

Right-click a request for the target lab and use one of the solver actions exposed by the extension.

## Notes

- The extension uses `HTTP_2_IGNORE_ALPN` for the HTTP/2 lab variants.
- For client-side desync mode, prefer the lab origin as input, for example `https://target-lab.net`, instead of localized paths such as `/en`.
- If a lab variant needs tuning, adjust constants in `src/main/java/beauty/burp/Http2TunnelSolverExtension.java`.

## Disclaimer

This project is intended for authorized lab and security research use only. Do not use it against systems without explicit permission.

## Author

Raghav Vivekanandan  
@ Ashtaksha Labs
