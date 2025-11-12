#!/usr/bin/env python3

import asyncio
import sys
from pathlib import Path
from prompt_toolkit import PromptSession
from prompt_toolkit.history import InMemoryHistory
from prompt_toolkit.styles import Style
import httpx
import pandas as pd

# Add project to path
sys.path.insert(0, str(Path(__file__).parent))

# Import configuration from ollama_mcp
from ollama_mcp import OLLAMA_HOST, CVE_CSV_PATH, read_csv_with_encoding, list_all_cves

# Reimplement the functions directly
async def check_status():
    """Check if Ollama server is running"""
    async with httpx.AsyncClient(timeout=5.0) as client:
        try:
            response = await client.get(f"{OLLAMA_HOST}/api/tags")
            if response.status_code == 200:
                return f"[OK] Ollama is up and running at {OLLAMA_HOST}"
            return f"[WARNING] Ollama responded with status {response.status_code}"
        except Exception as e:
            return f"[ERROR] Ollama not reachable at {OLLAMA_HOST}: {e}"

async def get_models():
    """List all available Ollama models"""
    async with httpx.AsyncClient(timeout=30.0) as client:
        try:
            response = await client.get(f"{OLLAMA_HOST}/api/tags")
            response.raise_for_status()
            data = response.json()
            models = [m["name"] for m in data.get("models", [])]
            if not models:
                return "[WARNING] No Ollama models installed. Use `ollama pull <model>` to add one."
            return "Available Ollama Models:\n" + "\n".join(f"- {m}" for m in models)
        except httpx.HTTPError as e:
            return f"[ERROR] Failed to connect to Ollama at {OLLAMA_HOST}: {str(e)}"

async def generate_text(model: str, prompt: str, temperature: float = 0.7, max_tokens: int = 512):
    """Generate text using Ollama"""
    async with httpx.AsyncClient(timeout=120.0) as client:
        payload = {
            "model": model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": temperature,
                "num_predict": max_tokens
            }
        }
        
        try:
            response = await client.post(f"{OLLAMA_HOST}/api/generate", json=payload)
            response.raise_for_status()
            
            data = response.json()
            output = data.get("response", "")
            
            if not output:
                return "[WARNING] No response received from Ollama model."
            
            return output.strip()
            
        except httpx.HTTPStatusError as e:
            return f"[ERROR] HTTP Error {e.response.status_code}: {e.response.text}"
        except httpx.RequestError as e:
            return f"[ERROR] Connection Error: {str(e)}"
        except Exception as e:
            return f"[ERROR] Unexpected error: {type(e).__name__}: {str(e)}"

def search_cve(cve_id: str):
    """Search for a CVE in the database"""
    cve_id = cve_id.strip()
    
    if not cve_id:
        return "Error: CVE_ID is required"
    
    if not CVE_CSV_PATH.exists():
        return f"Error: CVE database file not found at {CVE_CSV_PATH}"
    
    try:
        df = read_csv_with_encoding(CVE_CSV_PATH)
        
        if "CVE_ID" not in df.columns:
            return f"Error: 'CVE_ID' column not found"
        
        matching_rows = df[df["CVE_ID"].str.strip() == cve_id]
        
        if matching_rows.empty:
            return f"CVE+ID '{cve_id}' not found in the database"
        
        result = f"CVE Found: {cve_id}\n"
        result += "=" * 40 + "\n"
        
        row = matching_rows.iloc[0]
        
        for column, value in row.items():
            if pd.notna(value):
                result += f"{column}: {value}\n"
        
        return result
            
    except Exception as e:
        return f"Error reading CVE database: {str(e)}"

def get_statistics():
    """Get CVE statistics"""
    if not CVE_CSV_PATH.exists():
        return f"Error: CVE database file not found at {CVE_CSV_PATH}"
    
    try:
        df = read_csv_with_encoding(CVE_CSV_PATH)
        
        result = "CVE Database Statistics\n"
        result += "=" * 60 + "\n\n"
        
        result += f"Total CVE entries: {len(df)}\n"
        result += f"Total columns: {len(df.columns)}\n\n"
        
        result += "Column Information:\n"
        result += "-" * 60 + "\n"
        for column in df.columns:
            non_null = df[column].notna().sum()
            null_count = df[column].isna().sum()
            result += f"  - {column}:\n"
            result += f"      Non-null: {non_null} ({non_null/len(df)*100:.1f}%)\n"
            result += f"      Null: {null_count} ({null_count/len(df)*100:.1f}%)\n"
        
        # Additional statistics for numeric columns
        numeric_columns = df.select_dtypes(include=['number']).columns
        if len(numeric_columns) > 0:
            result += "\nNumeric Column Statistics:\n"
            result += "-" * 60 + "\n"
            for column in numeric_columns:
                result += f"  - {column}:\n"
                result += f"      Mean: {df[column].mean():.2f}\n"
                result += f"      Median: {df[column].median():.2f}\n"
                result += f"      Min: {df[column].min():.2f}\n"
                result += f"      Max: {df[column].max():.2f}\n"
        
        return result
        
    except Exception as e:
        return f"Error reading CVE database: {str(e)}"

class MCPChatClient:
    def __init__(self):
        self.session = PromptSession(history=InMemoryHistory())
        self.current_model = "llama3.2"
        self.conversation_history = []
        
    async def start(self):
        """Start the interactive chat session"""
        print("=" * 70)
        print("MCP + Ollama Terminal Chat Client")
        print("=" * 70)
        
        # Check status
        print("\nChecking Ollama connection...")
        status = await check_status()
        print(status)
        
        if "[ERROR]" in status:
            print("\nPlease start Ollama first: ollama serve")
            return
        
        models = await get_models()
        print(models)
        
        print("\n" + "=" * 70)
        print("Commands:")
        print("  /model <name>  - Switch model")
        print("  /models        - List available models")
        print("  /cve <id>      - Search for CVE")
        print("  /stats         - Show CVE statistics")
        print("  /clear         - Clear conversation history")
        print("  /list_cves     - List all CVEs in database")
        print("  /exit or /quit - Exit chat")
        print("=" * 70)
        
        print(f"\nUsing model: {self.current_model}")
        print("Type your message and press Enter...\n")
        
        while True:
            try:
                # Get user input
                user_input = await self.session.prompt_async(
                    "\nYou: ",
                )
                
                if not user_input.strip():
                    continue
                
                # Handle commands
                if user_input.startswith('/'):
                    await self.handle_command(user_input)
                    continue
                
                # Generate response
                print(f"\n{self.current_model}: ", end='', flush=True)
                
                response = await generate_text(
                    model=self.current_model,
                    prompt=user_input,
                    temperature=0.2,
                    max_tokens=512
                )
                
                print(response)
                
                # Save to history
                self.conversation_history.append({
                    "user": user_input,
                    "assistant": response
                })
                
            except KeyboardInterrupt:
                print("\n\nGoodbye!")
                break
            except EOFError:
                print("\n\nGoodbye!")
                break
            except Exception as e:
                print(f"\n[ERROR] {e}")
    
    async def handle_command(self, command: str):
        """Handle special commands"""
        parts = command.split(maxsplit=1)
        cmd = parts[0].lower()
        arg = parts[1] if len(parts) > 1 else None
        
        if cmd in ['/exit', '/quit']:
            print("\nGoodbye!")
            sys.exit(0)
        
        elif cmd == '/model':
            if arg:
                self.current_model = arg
                print(f"[OK] Switched to model: {self.current_model}")
            else:
                print(f"Current model: {self.current_model}")
        
        elif cmd == '/models':
            models = await get_models()
            print(f"\n{models}")
        
        elif cmd == '/cve':
            if arg:
                result = search_cve(arg)
                print(f"\n{result}")
            else:
                print("[ERROR] Usage: /cve <CVE_ID>")
        elif cmd == '/list_cves':
            all_cves = list_all_cves()
        elif cmd == '/stats':
            result = get_statistics()
            print(f"\n{result}")
        
        elif cmd == '/clear':
            self.conversation_history = []
            print("[OK] Conversation history cleared")
        
        else:
            print(f"[ERROR] Unknown command: {cmd}")

async def main():
    client = MCPChatClient()
    await client.start()

if __name__ == "__main__":
    asyncio.run(main())