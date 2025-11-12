#!/usr/bin/env python3

import os
from fastmcp import FastMCP
from typing import Optional, Dict, Any
import httpx
from dotenv import load_dotenv
from pathlib import Path
import pandas as pd

"""
# Create a .env file with the following content:
OLLAMA_HOST=http://localhost:11434

"""

# Load environment variables from .env file
load_dotenv()

# Initialize the MCP server
mcp = FastMCP(
    name="ollama-mcp",
    version="1.0.0",
    dependencies=["httpx", "python-dotenv", "pandas"],
    instructions="""You are an AI assistant connected to local Ollama models.
    You can query any installed Ollama model for text generation, code writing, or reasoning.
    Provide concise and context-aware responses.
    Always verify that the model exists before attempting to generate text.
    """
)

# Base Ollama configuration
OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")

# ----------------------------
# Utility: Call Ollama API
# ----------------------------
async def query_ollama(model: str, prompt: str, options: Optional[Dict[str, Any]] = None) -> str:
    """
    Sends a generation request to an Ollama model via its REST API.

    Args:
        model: Name of the Ollama model (e.g., 'llama3', 'mistral', 'codellama')
        prompt: Text prompt to send to the model
        options: Optional parameters such as temperature, top_p, max_tokens, etc.

    Returns:
        The model's text output as a string.
    """
    async with httpx.AsyncClient(timeout=120.0) as client:
        payload = {"model": model, "prompt": prompt}
        if options:
            payload["options"] = options
        
        try:
            response = await client.post(f"{OLLAMA_HOST}/api/generate", json=payload)
            response.raise_for_status()
        except httpx.HTTPError as e:
            return f"Error communicating with Ollama API: {str(e)}"
        
        # Ollama streams responses line by line, but we can read full text
        lines = response.text.splitlines()
        output = ""
        for line in lines:
            if not line.strip():
                continue
            try:
                data = httpx.Response(200, content=line).json()
                output += data.get("response", "")
            except Exception:
                continue
        return output.strip() if output else "No response received from Ollama model."
    
@mcp.tool()
async def check_ollama_status() -> str:
    """
    Check if Ollama server is running and responding.
    """
    async with httpx.AsyncClient(timeout=5.0) as client:
        try:
            response = await client.get(f"{OLLAMA_HOST}/api/tags")
            if response.status_code == 200:
                return f"[OK] Ollama is up and running at {OLLAMA_HOST}"
            return f"[WARNING] Ollama responded with status {response.status_code}"
        except Exception as e:
            return f"[ERROR] Ollama not reachable at {OLLAMA_HOST}: {e}"

# ----------------------------
# MCP Tool: List available models
# ----------------------------
PROJECT_FOLDER = Path(__file__).parent
CVE_CSV_PATH = PROJECT_FOLDER / "critical_cves_2016_2025.csv"

@mcp.tool()
async def list_models() -> str:
    """
    List all available Ollama models installed locally.
    """
    async with httpx.AsyncClient(timeout=30.0) as client:
        try:
            response = await client.get(f"{OLLAMA_HOST}/api/tags")
            response.raise_for_status()
            data = response.json()
            models = [m["name"] for m in data.get("models", [])]
            if not models:
                return "No Ollama models installed. Use `ollama pull <model>` to add one."
            return "🧠 Available Ollama Models:\n" + "\n".join(f"- {m}" for m in models)
        except httpx.HTTPError as e:
            return f"Failed to connect to Ollama at {OLLAMA_HOST}: {str(e)}"

def read_csv_with_encoding(file_path: Path) -> pd.DataFrame:
    """
    Read CSV file trying different encodings
    
    Args:
        file_path: Path to the CSV file
    
    Returns:
        pandas DataFrame
    """
    encodings = ['utf-8', 'latin-1', 'iso-8859-1', 'cp1252', 'utf-16']
    
    for encoding in encodings:
        try:
            df = pd.read_csv(file_path, encoding=encoding)
            return df
        except (UnicodeDecodeError, UnicodeError):
            continue
        except Exception as e:
            raise e
    
    # If all encodings fail
    raise ValueError(f"Could not read file with any of the attempted encodings: {encodings}")

@mcp.tool()
def search_cve(cve_id: str) -> str:
    """
    Search for a specific CVE_ID in the system's CVE database using pandas
    
    Args:
        cve_id: CVE identifier to search for (e.g., 'CVE-2023-1234')
    
    Returns:
        Formatted CVE information or error message
    """
    cve_id = cve_id.strip()
    
    if not cve_id:
        return "Error: CVE_ID is required"
    
    if not CVE_CSV_PATH.exists():
        return f"Error: CVE database file not found at {CVE_CSV_PATH}"
    
    try:
        # Read CSV using pandas with encoding handling
        df = read_csv_with_encoding(CVE_CSV_PATH)
        
        # Check if CVE_ID column exists
        if "CVE_ID" not in df.columns:
            return f"Error: 'CVE_ID' column not found. Available columns: {', '.join(df.columns)}"
        
        # Search for the CVE_ID
        matching_rows = df[df["CVE_ID"].str.strip() == cve_id]
        
        if matching_rows.empty:
            return f"CVE_ID '{cve_id}' not found in the database"
        
        # Format the found CVE information
        result = f"CVE Found: {cve_id}\n"
        result += "=" * 40 + "\n"
        
        # Get the first matching row
        row = matching_rows.iloc[0]
        
        for column, value in row.items():
            result += f"{column}: {value}\n"
        
        return result
            
    except FileNotFoundError:
        return f"Error: CVE database file not found at {CVE_CSV_PATH}"
    except Exception as e:
        return f"Error reading CVE database: {str(e)}"

@mcp.tool()
def list_all_cves(limit: int = 100) -> str:
    """
    List all CVE_IDs in the system database using pandas
    
    Args:
        limit: Maximum number of CVEs to return (default: 100)
    
    Returns:
        List of CVE identifiers
    """
    if not CVE_CSV_PATH.exists():
        return f"Error: CVE database file not found at {CVE_CSV_PATH}"
    
    try:
        # Read CSV using pandas with encoding handling
        df = read_csv_with_encoding(CVE_CSV_PATH)
        
        result = "CVE Database Contents:\n"
        result += "=" * 40 + "\n"
        
        # Display column names
        result += f"Available fields: {', '.join(df.columns.tolist())}\n"
        result += "=" * 40 + "\n\n"
        
        # Limit the number of rows
        limited_df = df.head(limit)
        
        if limited_df.empty:
            result += "No CVE entries found in the database"
            return result
        
        # Display each entry
        for idx, row in limited_df.iterrows():
            result += f"Entry {idx + 1}:\n"
            for column, value in row.items():
                # Only show non-null and non-empty values
                if pd.notna(value) and str(value).strip():
                    result += f"  {column}: {value}\n"
            result += "\n"
        
        # Add summary
        total_rows = len(df)
        if total_rows > limit:
            result += f"\n... (showing first {limit} of {total_rows} entries)\n"
        
        result += f"\nTotal entries in database: {total_rows}\n"
        result += f"Entries displayed: {len(limited_df)}\n"
        
        return result
            
    except FileNotFoundError:
        return f"Error: CVE database file not found at {CVE_CSV_PATH}"
    except Exception as e:
        return f"Error reading CVE database: {str(e)}"

@mcp.tool()
def get_cve_statistics() -> str:
    """
    Get statistical summary of the CVE database using pandas
    
    Returns:
        Statistical information about the CVE database
    """
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
            result += f"  • {column}:\n"
            result += f"      Non-null: {non_null} ({non_null/len(df)*100:.1f}%)\n"
            result += f"      Null: {null_count} ({null_count/len(df)*100:.1f}%)\n"
        
        # Additional statistics for numeric columns
        numeric_columns = df.select_dtypes(include=['number']).columns
        if len(numeric_columns) > 0:
            result += "\nNumeric Column Statistics:\n"
            result += "-" * 60 + "\n"
            for column in numeric_columns:
                result += f"  • {column}:\n"
                result += f"      Mean: {df[column].mean():.2f}\n"
                result += f"      Median: {df[column].median():.2f}\n"
                result += f"      Min: {df[column].min():.2f}\n"
                result += f"      Max: {df[column].max():.2f}\n"
        
        return result
        
    except FileNotFoundError:
        return f"Error: CVE database file not found at {CVE_CSV_PATH}"
    except Exception as e:
        return f"Error reading CVE database: {str(e)}"

@mcp.tool()
def list_project_files(file_extension: Optional[str] = None) -> str:
    """
    List all files in the project folder, optionally filtered by extension
    
    Args:
        file_extension: Optional file extension to filter by (e.g., 'pdf', 'png', 'csv'). 
                       If None, lists all files
    
    Returns:
        List of files in the project folder
    """
    try:
        result = f"Project Folder: {PROJECT_FOLDER}\n"
        result += "=" * 60 + "\n"
        
        if file_extension:
            # Normalize extension (remove leading dot if present)
            ext = file_extension.lower().lstrip('.')
            result += f"Filtering by extension: .{ext}\n"
            result += "=" * 60 + "\n\n"
            files = sorted([f for f in PROJECT_FOLDER.iterdir() if f.is_file() and f.suffix.lower() == f'.{ext}'])
        else:
            result += "Listing all files\n"
            result += "=" * 60 + "\n\n"
            files = sorted([f for f in PROJECT_FOLDER.iterdir() if f.is_file()])
        
        if not files:
            if file_extension:
                result += f"No .{ext} files found in the project folder"
            else:
                result += "No files found in the project folder"
            return result
        
        # Create a DataFrame for better organization
        file_data = []
        for file_path in files:
            ext = file_path.suffix.lower() or 'no extension'
            file_size = file_path.stat().st_size
            
            # Format file size
            if file_size < 1024:
                size_str = f"{file_size} B"
            elif file_size < 1024 * 1024:
                size_str = f"{file_size / 1024:.1f} KB"
            else:
                size_str = f"{file_size / (1024 * 1024):.1f} MB"
            
            file_data.append({
                'Extension': ext,
                'Filename': file_path.name,
                'Size': size_str,
                'Size_bytes': file_size
            })
        
        # Create DataFrame
        files_df = pd.DataFrame(file_data)
        
        # Group by extension
        for ext in sorted(files_df['Extension'].unique()):
            ext_files = files_df[files_df['Extension'] == ext]
            result += f"\n{ext.upper()} files:\n"
            result += "-" * 40 + "\n"
            for _, row in ext_files.iterrows():
                result += f"  • {row['Filename']} ({row['Size']})\n"
        
        result += f"\n{'=' * 60}\n"
        result += f"Total files: {len(files)}\n"
        
        # Summary by extension
        result += "\nSummary by extension:\n"
        extension_summary = files_df.groupby('Extension').agg({
            'Filename': 'count',
            'Size_bytes': 'sum'
        }).rename(columns={'Filename': 'Count'})
        
        for ext, row in extension_summary.iterrows():
            size_bytes = row['Size_bytes']
            if size_bytes < 1024:
                size_str = f"{size_bytes} B"
            elif size_bytes < 1024 * 1024:
                size_str = f"{size_bytes / 1024:.1f} KB"
            else:
                size_str = f"{size_bytes / (1024 * 1024):.1f} MB"
            
            result += f"  {ext}: {row['Count']} file(s), Total size: {size_str}\n"
        
        return result
        
    except Exception as e:
        return f"Error listing project files: {str(e)}"
    
# ----------------------------
# MCP Tool: Generate text using Ollama
# ----------------------------
@mcp.tool()
async def generate_with_ollama(
    model: str,
    prompt: str,
    temperature: Optional[float] = 0.2,
    max_tokens: Optional[int] = 512
) -> str:
    """
    Generate a text response from a specified Ollama model.

    Args:
        model: Model name (e.g., 'llama3', 'mistral', 'codellama')
        prompt: Prompt text to send to the model
        temperature: Sampling temperature (0.0–1.0)
        max_tokens: Maximum number of tokens to generate

    Returns:
        Model-generated text response
    """
    options = {
        "temperature": temperature,
        "num_predict": max_tokens
    }
    result = await query_ollama(model, prompt, options)
    return f"🤖 Model: {model}\n\n{result}"

# Run MCP server
if __name__ == "__main__":
    mcp.run()
    # mcp.run(transport="http", host="localhost", port=8765) # comment out to use locally
