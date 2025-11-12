# MCP Server CLI using Ollama

This repo is an example of how to set up and run an MCP server using the Ollama model serving platform. The goal is to provide a CLI-based way to interact with agents through command line.

Additional MCP tools are to be added to `ollama_mcp.py`.

Future migration to Gonzaga's GPU server is on the way and will be updated.

## Step 1: Install Dependencies
```bash
pip install fastmcp httpx python-dotenv pandas mcp-cli
pip install ollama
```

## Step 2: Set Up Environment Variables
Clone your repo and create a `.env` file that contains the address of your Ollama server:
```bash
OLLAMA_HOST=http://localhost:11434
```

## Step 3: Start Ollama
Make sure your Ollama server is running locally
```bash
ollama pull llama3.2:latest
ollama serve
```

## Step 4: Run the MCP Server
Run the MCP server using the following command:
```bash
mcp-cli --server ollama_mcp --model llama3.2:latest
```