    
git clone https://github.com/hieulw/cicflowmeter
  
cd cicflowmeter
uv sync # Or if uv is not installed, use `python -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt`


# 1. Crea un virtual environment per il detector
python3 -m venv venv_detector

# 2. Attivalo
source venv_detector/bin/activate

# 3. Installa le librerie necessarie (pandas, sklearn, joblib)
pip install -r requirements.txt

# 4. Disattiva per ora (lo useremo dopo col comando specifico)
deactivate

sudo ./venv_detector/bin/python3 realtime_detector.py

