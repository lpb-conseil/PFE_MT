import sys, os, logging
logging.basicConfig(level=logging.INFO, format="%(name)s: %(message)s")
sys.path.insert(0, r'C:\Users\MattéoTREMISI\OneDrive - LPB Conseil\Bureau\CESI\PFE\dashboard')
os.chdir(r'C:\Users\MattéoTREMISI\OneDrive - LPB Conseil\Bureau\CESI\PFE\dashboard')
import db; db.init_db()
from collectors.run_collect import run
result = run()
print("RESULT:", result)
