import yaml
import os

def load_config(config_path: str = None) -> dict:
    if config_path is None:
        # Get the directory of this file and construct the path to config.yaml
        current_dir = os.path.dirname(os.path.abspath(__file__))
        config_path = os.path.join(current_dir, "..", "config", "config.yaml")
    
    with open(config_path, "r") as file:
        config = yaml.safe_load(file)
        # print(config)
    return config