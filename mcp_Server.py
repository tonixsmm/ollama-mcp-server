#!/usr/bin/env python3
"""
Install dependencies first:
pip install fastmcp PyPDF2 pandas
"""

import csv
import base64
from pathlib import Path
from typing import Optional
from fastmcp import FastMCP
import PyPDF2
import pandas as pd

# Initialize FastMCP server with metadata
mcp = FastMCP(
    name="AI-Copilot",
    version="1.0.0",
    instructions=""""""
)

# Define project folder and CVE database path
PROJECT_FOLDER = Path(__file__).parent
CVE_CSV_PATH = PROJECT_FOLDER / "critical_cves_2016_2025.csv"


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
            # If it's not an encoding error, raise it
            raise e
    
    # If all encodings fail
    raise ValueError(f"Could not read file with any of the attempted encodings: {encodings}")




@mcp.tool()
def search_cve(cve_id: str) -> str:
    """
    Search for a specific CVE-ID in the system's CVE database using pandas
    
    Args:
        cve_id: CVE identifier to search for (e.g., 'CVE-2023-1234')
    
    Returns:
        Formatted CVE information or error message
    """
    cve_id = cve_id.strip()
    
    if not cve_id:
        return "Error: CVE-ID is required"
    
    if not CVE_CSV_PATH.exists():
        return f"Error: CVE database file not found at {CVE_CSV_PATH}"
    
    try:
        # Read CSV using pandas with encoding handling
        df = read_csv_with_encoding(CVE_CSV_PATH)
        
        # Check if CVE-ID column exists
        if "CVE-ID" not in df.columns:
            return f"Error: 'CVE-ID' column not found. Available columns: {', '.join(df.columns)}"
        
        # Search for the CVE-ID
        matching_rows = df[df["CVE-ID"].str.strip() == cve_id]
        
        if matching_rows.empty:
            return f"CVE-ID '{cve_id}' not found in the database"
        
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
    List all CVE-IDs in the system database using pandas
    
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


# Run the server
if __name__ == "__main__":
    mcp.run()