import os
import pickle
import subprocess as sp
import yaml

SECRET_KEY = "super_secret_password_123"

def execute_user_command(user_cmd: str):
    os.system(user_cmd)
    sp.run(user_cmd, shell=True)

def load_data(data_bytes):
    pickle.loads(data_bytes)
    yaml.load(data_bytes)
