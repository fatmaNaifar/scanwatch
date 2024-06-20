import pandas as pd
import requests
from datetime import datetime
from flask import Flask, request, jsonify, redirect, url_for, render_template
import threading
import schedule
import time
from rethinkdb import RethinkDB
r = RethinkDB()
import os

# Fetching connection details from environment variables
RETHINKDB_HOST = os.getenv('RETHINKDB_HOST', 'localhost')
RETHINKDB_PORT = int(os.getenv('RETHINKDB_PORT', 28015))
# Withings API credentials
CLIENT_ID = '36eff5960dbee78d215040ff5cdc737edc2c6f6a8e12e6e24a6a699258be466d'
CLIENT_SECRET = 'f57f5bf2b8052719bc691b78d9d23631b9ddcce2b41d2f133daf62b64cd4182a'
REDIRECT_URI = 'http://localhost:3200'
STATE = '11136964'

# Connect to RethinkDB
conn = r.connect(host=RETHINKDB_HOST,
                 port=RETHINKDB_PORT,
                 db='healthy')
app = Flask(__name__)
withings_api = None
authorization_code = None
email = None

class WithingsAPI:
    def __init__(self):
        self.client_id = CLIENT_ID
        self.client_secret = CLIENT_SECRET
        self.redirect_uri = REDIRECT_URI
        self.access_token = None
        self.refresh_token = None
        self.expires_in = None

    def get_authorization_url(self):
        return (
            f"https://account.withings.com/oauth2_user/authorize2"
            f"?response_type=code&client_id={self.client_id}&scope=user.info,user.metrics,user.activity"
            f"&redirect_uri={self.redirect_uri}&state={STATE}"
        )

    def request_access_token(self, authorization_code):
        token_url = 'https://wbsapi.withings.net/v2/oauth2'
        token_params = {
            'action': 'requesttoken',
            'grant_type': 'authorization_code',
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'code': authorization_code,
            'redirect_uri': self.redirect_uri,
        }
        response = requests.post(token_url, data=token_params)
        response_json = response.json()

        if response_json['status'] != 0:
            raise Exception(f"Error: {response_json}")

        self.access_token = response_json['body']['access_token']
        self.refresh_token = response_json['body']['refresh_token']
        self.expires_in = datetime.utcnow().timestamp() + response_json['body']['expires_in']

    def is_token_expired(self):
        if not self.expires_in:
            return True
        expiration_datetime = datetime.utcfromtimestamp(self.expires_in)
        current_time = datetime.utcnow()
        return current_time >= expiration_datetime

    def refresh_access_token(self):
        url = 'https://wbsapi.withings.net/v2/oauth2'
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        data = {
            'action': 'requesttoken',
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'grant_type': 'refresh_token',
            'refresh_token': self.refresh_token,
        }
        response = requests.post(url, headers=headers, data=data)
        if response.status_code == 200:
            data = response.json()
            if 'body' in data:
                self.access_token = data['body']['access_token']
                self.expires_in = datetime.utcnow().timestamp() + data['body']['expires_in']
            else:
                raise Exception(f"Error: No 'body' in response - {data}")
        else:
            raise Exception(f"Error: {response.status_code} - {response.text}")


def save_user_data(email, access_token, refresh_token, expires_in):
    r.table("users").insert({
        'id': email,
        'access_token': access_token,
        'refresh_token': refresh_token,
        'expires_in': expires_in
    }).run(conn)

def get_user_data(email):
    return r.table('users').get(email).run(conn)

@app.route('/')
def index():
    global authorization_code
    authorization_code = request.args.get('code')
    received_state = request.args.get('state')
    if authorization_code and received_state == STATE:
        return redirect(url_for('email_form'))
    else:
        auth_url = withings_api.get_authorization_url()
        return f'Please authorize the application by visiting this URL: <a href="{auth_url}">{auth_url}</a>'

@app.route('/email-form')
def email_form():
    return render_template('email_form.html')

@app.route('/send-email', methods=['POST'])
def send_email():
    global email
    email = request.form.get('email')
    if email:
        print(f"Received email: {email}")
        threading.Thread(target=process_withings_data).start()
        return 'Thank you, you can close this window'
    else:
        return jsonify({'status': 'error', 'message': 'Email not provided'}), 400

def process_withings_data():
    try:
        withings_api.request_access_token(authorization_code)
        if withings_api.is_token_expired():
            withings_api.refresh_access_token()
        save_user_data(email, withings_api.access_token, withings_api.refresh_token, withings_api.expires_in)
        fetch_withings_data(email)
    except Exception as e:
        print(f"An error occurred during Withings data processing: {e}")

def fetch_withings_data(email):
    user_data = get_user_data(email)
    if not user_data:
        print("No user data found for this email.")
        return

    access_token = user_data['access_token']
    refresh_token = user_data['refresh_token']
    expires_in = user_data['expires_in']

    if withings_api.is_token_expired():
        withings_api.refresh_access_token()

    fetch_and_store_user_data(email, access_token)

def fetch_and_store_user_data(email, access_token):
    headers = {'Authorization': 'Bearer ' + access_token}

    # GET MEASURES
    url = 'https://wbsapi.withings.net/measure'
    headers = {'Authorization': 'Bearer ' + withings_api.access_token}
    data = {"action": "getmeas", "meastypes": '1,71,4,11,54,130,135,136,137,138', "category": 1}
    response = requests.post(url, headers=headers, data=data)
    if response.status_code == 200:
        result = response.json()
    else:
        print(f"Error: {response.status_code} - {response.text}")
        return

    measures_list = []
    measuregrps = result['body']['measuregrps']
    for measuregrp in measuregrps:
        measures_list.extend(measuregrp['measures'])

    df_measures = pd.json_normalize(measures_list)
    df_SPO2 = df_measures[df_measures['type'] == 54].copy()
    SPO2_data = df_SPO2[["value"]]
    SPO2_dict = {str(k): v for k, v in SPO2_data.to_dict(orient='index').items()}
    r.table('users').get(email).update({'SPO2': SPO2_dict}).run(conn)

    # ACTIVITIES
    url = 'https://wbsapi.withings.net/v2/measure'
    start_date = '2024-02-07'
    end_date = datetime.now().strftime("%Y-%m-%d")
    params = {
        'action': 'getactivity',
        'startdateymd': start_date,
        'enddateymd': end_date,
        'data_fields': 'steps,distance,elevation,soft,moderate,intense,active,calories,totalcalories,hr_average,hr_min,hr_max,hr_zone_0,hr_zone_1,hr_zone_2,hr_zone_3'
    }
    response = requests.post(url, headers=headers, data=params)
    if response.status_code == 200:
        data = response.json()
    else:
        print(f"Error: {response.status_code}")
        print(response.text)
        return

    activities_data = data['body']['activities']
    df = pd.json_normalize(activities_data)
    heart_rate_avg = df[["hr_average", "date"]]
    df_heart_rate_avg = pd.DataFrame(heart_rate_avg).dropna()
    hr_dict = {str(k): v for k, v in df_heart_rate_avg.to_dict(orient='index').items()}
    r.table('users').get(email).update({'heartRate_avg': hr_dict}).run(conn)

    # ECG LIST
    url_list = 'https://wbsapi.withings.net/v2/heart'
    data_list = {'action': 'list'}
    response_list = requests.post(url_list, headers=headers, data=data_list)
    if response_list.status_code == 200:
        result_list = response_list.json()
        ECG_list = result_list['body']['series']
        signal_ids = [ecg['ecg']['signalid'] for ecg in ECG_list]
        df_ecg_list = pd.json_normalize(ECG_list)
        url_get = 'https://wbsapi.withings.net/v2/heart'
        all_signal_data = []

        for signal_id in signal_ids:
            data_get = {'action': 'get', 'signalid': signal_id}
            response_get = requests.post(url_get, headers=headers, data=data_get)
            if response_get.status_code == 200:
                signal_data = response_get.json()
                all_signal_data.append(signal_data['body'])
            else:
                print(f"Error for Signal ID {signal_id}: {response_get.status_code}")
                print(response_get.text)

        df_all_signals = pd.json_normalize(all_signal_data)
        ECG_df = pd.merge(df_ecg_list, df_all_signals, left_index=True, right_index=True,
                          suffixes=('_ecg_list', '_ecg_data'))

        ECG_record = ECG_df[["ecg.signalid", "signal", "timestamp", "ecg.afib", "heart_rate.value"]]
        df_ECG_record = pd.DataFrame(ECG_record)
        df_ECG_record['timestamp'] = pd.to_datetime(df_ECG_record['timestamp'], unit='s')
        df_ECG_record['date'] = df_ECG_record['timestamp'].dt.strftime('%Y-%m-%d-%H-%M-%S')
        df_ECG_record = df_ECG_record.rename(
            columns={'ecg.signalid': 'signalId', 'timestamp': 'date', 'ecg.afib': 'afib',
                     'heart_rate.value': 'heart_rate'}).dropna()

        ECG_dict = df_ECG_record.to_dict(orient='records')
        r.table('users').get(email).update({'ECG': ECG_dict}).run(conn)
    else:
        print(f"Error for ECGLIST API: {response_list.status_code}")
        print(response_list.text)


def job():
    users = r.table('users').run(conn)
    for user in users:
        email = user['id']
        print(f"Fetching data for {email}")
        fetch_withings_data(email)

# Schedule the job to run every 2 minutes
schedule.every(1).minutes.do(job)

def scheduler_thread():
    while True:
        schedule.run_pending()
        time.sleep(1)

# Start the scheduler thread
threading.Thread(target=scheduler_thread).start()

if __name__ == '__main__':
    withings_api = WithingsAPI()
    app.run(port=3200, debug=True)
