"""
Seed Qdrant from CSIC2010 dataset on Hugging Face
Dataset: https://huggingface.co/datasets/nquangit/CSIC2010_dataset_classification
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from datasets import load_dataset
from backends.rag_backend import add_rag_example

def seed_qdrant_from_csic():
    print("Loading CSIC2010 dataset from Hugging Face...")
    
    try:
        dataset = load_dataset("nquangit/CSIC2010_dataset_classification", split="train")
    except Exception as e:
        print(f"Error loading dataset: {e}")
        print("Make sure you have 'datasets' package installed: pip install datasets")
        sys.exit(1)
    
    print(f"Dataset loaded. Total rows: {len(dataset)}")
    print(f"Columns: {dataset.column_names}")
    
    # Inspect first row to understand structure
    if len(dataset) > 0:
        print(f"\nFirst row example:\n{dataset[0]}")
    
    # Seed Qdrant (using 'request' and 'label' or 'class' column)
    # Adjust column names based on actual dataset structure
    col_request = None
    col_label = None
    
    for col in dataset.column_names:
        if col.lower() in ["request", "requests", "http_request", "payload", "text"]:
            col_request = col
        if col.lower() in ["label", "labels", "class", "classification", "attack_type"]:
            col_label = col
    
    if not col_request or not col_label:
        print(f"\nWarning: Could not auto-detect request/label columns")
        print(f"Available columns: {dataset.column_names}")
        col_request = input("Enter request column name: ")
        col_label = input("Enter label column name: ")
    
    print(f"\nSeeding Qdrant using columns: request='{col_request}', label='{col_label}'")
    
    count = 0
    batch_size = 100
    
    for idx, row in enumerate(dataset):
        request = row.get(col_request, "")
        label_value = row.get(col_label, "Unknown")
        
        if request and label_value is not None:
            try:
                # Determine if anomalous (label: 0=normal, 1=attack)
                if isinstance(label_value, int):
                    is_anomalous = label_value == 1
                    attack_type = "attack" if is_anomalous else "normal"
                else:
                    label_str = str(label_value).lower()
                    is_anomalous = label_str not in ["normal", "0"]
                    attack_type = str(label_value)
                
                # Add to RAG
                add_rag_example(
                    text=str(request),
                    is_anomalous=is_anomalous,
                    attack_type=attack_type
                )
                count += 1
                
                if (idx + 1) % batch_size == 0:
                    print(f"  Seeded {idx + 1} examples...")
            except Exception as e:
                print(f"  Error seeding row {idx}: {e}")
    
    print(f"\n✅ Successfully seeded {count} examples to Qdrant")
    return count


if __name__ == "__main__":
    seed_qdrant_from_csic()
