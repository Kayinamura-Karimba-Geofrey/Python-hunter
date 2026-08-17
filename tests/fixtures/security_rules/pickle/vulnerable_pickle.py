import pickle

def load_payload(raw_bytes):
    return pickle.loads(raw_bytes)
