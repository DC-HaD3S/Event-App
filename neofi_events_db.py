from sqlalchemy import create_engine
engine = create_engine("sqlite:///neofi_events.db")
engine.connect()
print("Database connection successful")