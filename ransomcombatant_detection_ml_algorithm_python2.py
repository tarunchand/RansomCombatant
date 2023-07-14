
import json
import pandas as pd

with open('Results/Normal-Windows-Process-2/network_activity', 'r') as f:
  network_activity_normal = json.load(f)
with open('Results/Normal-Windows-Process-2/resource_activity', 'r') as f:
  resource_activity_normal = json.load(f)

variants = ["WannaCry-3", "NotPetya", "Ryuk", "Maze-Ransomware", "Cerber"]

network_activity_ransomwares = []
resource_activity_ransomwares = []

for variant in variants:
  with open('Results/{}/resource_activity'.format(variant), 'r') as f:
    resource_activity_ransomware = json.load(f)
  with open('Results/{}/network_activity'.format(variant), 'r') as f:
    network_activity_ransomware = json.load(f)
  network_activity_ransomwares.append(network_activity_ransomware)
  resource_activity_ransomwares.append(resource_activity_ransomware)

ransomware_programs = ['ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa.exe', 'cscript.exe', '@WanaDecryptor@.exe', '51B4EF5DC9D26B7A26E214CEE90598631E2EAA67.exe', 'E906FA3D51E86A61741B3499145A114E9BFB7C56.exe', 'ryuk.exe', 'rmTdq.exe', 'wordupd.exe', 'cerber.exe']

avg_cpu = dict()
avg_ram = dict()
avg_read_bytes = dict()
avg_write_bytes = dict()
avg_read_count = dict()
avg_write_count = dict()

dataframe_dict = dict({
    'Pid': [],
    'Process_Name': [],
    'CPU': [],
    'RAM': [], 
    'Read_Bytes': [],
    'Write_Bytes': [],
    'Read_Count': [],
    'Write_Count': [],
    'isRansomware': []
})

for key, val in resource_activity_normal.items():
  pid, process_name = key.split(':')
  dataframe_dict['Pid'].append(pid)
  dataframe_dict['Process_Name'].append(process_name)
  dataframe_dict['isRansomware'].append(0)
  dataframe_dict['CPU'].append(sum(val['cpu_percent'])/len(val['cpu_percent']))
  dataframe_dict['RAM'].append(sum(val['ram'])/len(val['ram']))
  dataframe_dict['Read_Bytes'].append(sum(val['read_bytes'])/len(val['read_bytes']))
  dataframe_dict['Write_Bytes'].append(sum(val['write_bytes'])/len(val['write_bytes']))
  dataframe_dict['Read_Count'].append(sum(val['read_count'])/len(val['read_count']))
  dataframe_dict['Write_Count'].append(sum(val['write_count'])/len(val['write_count']))

for resource_activity in resource_activity_ransomwares:
  for key, val in resource_activity.items():
    pid, process_name = key.split(':')
    dataframe_dict['Pid'].append(pid)
    dataframe_dict['Process_Name'].append(process_name)
    if process_name in ransomware_programs:
      dataframe_dict['isRansomware'].append(1)
    else:
      dataframe_dict['isRansomware'].append(0)
    dataframe_dict['CPU'].append(sum(val['cpu_percent'])/len(val['cpu_percent']))
    dataframe_dict['RAM'].append(sum(val['ram'])/len(val['ram']))
    dataframe_dict['Read_Bytes'].append(sum(val['read_bytes'])/len(val['read_bytes']))
    dataframe_dict['Write_Bytes'].append(sum(val['write_bytes'])/len(val['write_bytes']))
    dataframe_dict['Read_Count'].append(sum(val['read_count'])/len(val['read_count']))
    dataframe_dict['Write_Count'].append(sum(val['write_count'])/len(val['write_count']))

training_data = pd.DataFrame(dataframe_dict)
# training_data

# pd.options.display.max_rows = 309
# training_data

input_features = ['CPU', 'RAM', 'Read_Bytes', 'Write_Bytes', 'Read_Count', 'Write_Count']
target_feature = 'isRansomware'

X = training_data[input_features]
Y = training_data[target_feature]

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import confusion_matrix

rf = RandomForestClassifier(n_estimators=100, class_weight="balanced")
rf.fit(X, Y)

# Y_pred = rf.predict(X)
# confusion_matrix(Y, Y_pred)

# rf.predict([[0, 2.525778e+07, 6.425343e+07, 1.671792e+09, 1013.953368, 6387.000000]])[0]

import pickle
with open("detect_ransomware.pkl", "wb") as f:
    pickle.dump(rf, f)
