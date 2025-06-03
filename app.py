from flask import Flask, request, jsonify
import json
import binascii
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import aiohttp
import asyncio
import urllib3
from datetime import datetime, timedelta
import os
from functools import lru_cache
import time

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from google.protobuf.json_format import MessageToJson
import uid_generator_pb2
import like_count_pb2

app = Flask(__name__)

def load_tokens(region):
    try:
        if region == "IND":
            with open("token_ind.json", "r") as f:
                tokens = json.load(f)
        elif region in {"BR", "US", "SAC", "NA"}:
            with open("token_br.json", "r") as f:
                tokens = json.load(f)
        else:
            with open("token_bd.json", "r") as f:
                tokens = json.load(f)
        return tokens
    except Exception:
        return None

def encrypt_message(plaintext):
    try:
        key = b'Yg&tc%DEuh6%Zc^8'
        iv = b'6oyZDr22E3ychjM%'
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_message = pad(plaintext, AES.block_size)
        encrypted_message = cipher.encrypt(padded_message)
        return binascii.hexlify(encrypted_message).decode('utf-8')
    except Exception:
        return None

def create_protobuf(uid):
    try:
        message = uid_generator_pb2.uid_generator()
        message.saturn_ = int(uid)
        message.garena = 1
        return message.SerializeToString()
    except Exception:
        return None

def enc(uid):
    protobuf_data = create_protobuf(uid)
    if protobuf_data is None:
        return None
    encrypted_uid = encrypt_message(protobuf_data)
    return encrypted_uid

def decode_protobuf(binary):
    try:
        items = like_count_pb2.Info()
        items.ParseFromString(binary)
        return items
    except Exception:
        return None

async def fetch_info(session, url, edata, headers):
    try:
        async with session.post(url, data=edata, headers=headers, ssl=False, timeout=5) as response:
            if response.status != 200:
                return None
            binary = await response.read()
            return decode_protobuf(binary)
    except Exception:
        return None

@app.route('/visit', methods=['GET'])
async def visit():
    target_uid = request.args.get("uid")
    region = request.args.get("region", "").upper()

    if not all([target_uid, region]):
        return jsonify({"error": "UID and region are required"}), 400

    try:
        tokens = load_tokens(region)
        if tokens is None:
            raise Exception("Failed to load tokens.")

        encrypted_target_uid = enc(target_uid)
        if encrypted_target_uid is None:
            raise Exception("Encryption of target UID failed.")

        if region == "IND":
            url = "https://client.ind.freefiremobile.com/GetPlayerPersonalShow"
        elif region in {"BR", "US", "SAC", "NA"}:
            url = "https://client.us.freefiremobile.com/GetPlayerPersonalShow"
        else:
            url = "https://clientbp.ggblueshark.com/GetPlayerPersonalShow"

        total_visits = len(tokens) * 20
        headers_template = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Content-Type': "application/x-www-form-urlencoded",
            'Expect': "100-continue",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': "OB49"
        }

        async with aiohttp.ClientSession() as session:
            tasks = []
            for token in tokens:
                for _ in range(20):
                    headers = headers_template.copy()
                    headers["Authorization"] = f"Bearer {token['token']}"
                    edata = bytes.fromhex(encrypted_target_uid)
                    tasks.append(fetch_info(session, url, edata, headers))

            raw_responses = await asyncio.gather(*tasks)

        success_count = 0
        failed_count = 0
        total_responses = []
        player_name = None

        for info in raw_responses:
            total_responses.append(info)
            if info:
                if not player_name:
                    jsone = MessageToJson(info)
                    data_info = json.loads(jsone)
                    player_name = data_info.get('AccountInfo', {}).get('PlayerNickname', '')
                success_count += 1
            else:
                failed_count += 1

        summary = {
            "TotalVisits": total_visits,
            "SuccessfulVisits": success_count,
            "FailedVisits": failed_count,
            "PlayerNickname": player_name,
            "UID": int(target_uid),
            "TotalResponses": total_responses
        }

        return jsonify(summary)

    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, use_reloader=False)