import os
import sys

print("=" * 40)
print("Starting setup...")
print("=" * 40)

# Create folders
os.makedirs("data", exist_ok=True)
os.makedirs("backend/models", exist_ok=True)

# Generate logs
if not os.path.exists("data/sample_logs.csv"):
    print("Generating sample logs...")
    ret = os.system(f"{sys.executable} data/generate_logs.py")
    print(f"Generate logs exit code: {ret}")
else:
    print("Sample logs already exist, skipping...")

# Train model
if not os.path.exists("backend/models/isolation_forest.pkl"):
    print("Training ML model...")
    ret = os.system(f"{sys.executable} ml/train_model.py")
    print(f"Train model exit code: {ret}")
else:
    print("Model already exists, skipping...")

# Setup database
print("Setting up database...")
try:
    from backend.utils.database import init_database
    init_database()
    print("Database initialized without replacing existing records.")
except Exception as e:
    print(f"Database error: {e}")
    raise

print("=" * 40)
print("Setup complete!")
print("=" * 40)