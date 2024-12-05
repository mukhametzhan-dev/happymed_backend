import sys,json
inputs = json.loads(sys.argv[1])
from tabulate import tabulate

class ScheduleAdapter:
    @staticmethod
    def json_to_string(schedule_json):
        try:
            return json.dumps(schedule_json, indent=4)
        except Exception as e:
            raise ValueError(f"Error converting JSON to string: {e}")
    @staticmethod
    def string_to_json(schedule_string):
        try:
            return json.loads(schedule_string)
        except Exception as e:
            raise ValueError(f"Error converting string to JSON: {e}")
    
    @staticmethod
    def visualize_schedule(schedule_json):
        try:
            table = [[entry["day"], entry["time"]] for entry in schedule_json]
            return tabulate(table, headers=["Day", "Time"], tablefmt="grid")
        except Exception as e:
            
            raise ValueError(f"Error visualizing schedule: {e}")
#[{"day": "tuesday", "time": ["13:00", "17:00"]}, {"day": "friday", "time": ["16:00", "17:00"]}, {"day": "sunday", "time": ["07:00", "10:00"]}, {"day": "thursday", "time": ["15:00", "19:00"]}, {"day": "monday", "time": ["11:00", "14:00"]}, {"day": "wednesday", "time": ["19:00", "21:00"]}, {"day": "saturday", "time": ["16:00", "18:00"]}]
