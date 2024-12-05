import json
from tabulate import tabulate
schedule_json = json.loads('[{"day": "tuesday", "time": ["13:00", "17:00"]}, {"day": "friday", "time": ["16:00", "17:00"]}, {"day": "sunday", "time": ["07:00", "10:00"]}, {"day": "thursday", "time": ["15:00", "19:00"]}, {"day": "monday", "time": ["11:00", "14:00"]}, {"day": "wednesday", "time": ["19:00", "21:00"]}, {"day": "saturday", "time": ["16:00", "18:00"]}]')
table = [[entry["day"], entry["time"]] for entry in schedule_json]
print(tabulate(table, headers=["Day", "Time"], tablefmt="grid"))