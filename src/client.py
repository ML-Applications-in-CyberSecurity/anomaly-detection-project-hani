import socket
import json
import pandas as pd
import joblib
from together import Together
import csv

HOST = 'localhost'
PORT = 9999

model = joblib.load("anomaly_model.joblib")
scaler = joblib.load("scaler.joblib")

TOGETHER_API_KEY = "tgp_v1_5Rk5uQj21QqJnbppqYrKPGDVR6tkmtOz--ud3370s68" 
client = Together(api_key=TOGETHER_API_KEY)

def pre_process_data(data):
    df = pd.DataFrame([data])
    
    df = pd.get_dummies(df, columns=['protocol'], drop_first=True)
    
    if 'protocol_UDP' not in df.columns:
        df['protocol_UDP'] = 0
    
    numeric_columns = ['src_port', 'dst_port', 'packet_size', 'duration_ms']
    df[numeric_columns] = scaler.transform(df[numeric_columns])
    
    features = ['src_port', 'dst_port', 'packet_size', 'duration_ms', 'protocol_UDP']
    return df[features]

csv_file = open("anomalies_log.csv", "a", newline='')
csv_writer = csv.writer(csv_file)
csv_writer.writerow(['src_port', 'dst_port', 'packet_size', 'duration_ms', 'protocol', 'label', 'reason', 'confidence_score'])

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    buffer = ""
    print("Client connected to server.\n")

    while True:
        chunk = s.recv(1024).decode()
        if not chunk:
            break
        buffer += chunk

        while '\n' in buffer:
            line, buffer = buffer.split('\n', 1)
            try:
                data = json.loads(line)
                print(f'Data Received:\n{data}\n')

                processed_data = pre_process_data(data)
                prediction = model.predict(processed_data)
                confidence_score = -model.score_samples(processed_data)[0]  
                
                if prediction[0] == -1:
                    messages = [
    {
        "role": "system",
        "content": (
            "You are a cybersecurity analyst. You receive a network traffic data point flagged as anomalous by an ML model. "
            "You also know the general profile of normal behavior, including acceptable ranges and typical values. "
            "Your task is to:\n"
            "1. Assign a short label describing the most likely anomaly (e.g., 'Suspicious Port', 'Large Packet', 'Long Duration', 'Unknown Protocol').\n"
            "2. Briefly explain why it's considered anomalous, considering not only hard thresholds but also proximity to boundaries.\n"
            "3. Treat values that are close to the edge of the normal range as 'borderline suspicious'.\n"
            "Output format:\nLabel: <label>\nReason: <reason>"
        )
    },
    {
        "role": "user",
        "content": (
            "Normal behavior:\n"
            "- src_port: typically 80, 443, 22, or 8080 (others might be suspicious)\n"
            "- packet_size: normal between 100 and 1500 bytes (values close to 1500 may still be risky)\n"
            "- duration_ms: normal between 50 and 500 ms (above 1500 ms is suspicious)\n"
            "- protocol: TCP and UDP are normal; ICMP or UNKNOWN are abnormal\n\n"
            f"Incoming data:\n"
            f"- src_port: {data['src_port']}\n"
            f"- dst_port: {data['dst_port']}\n"
            f"- packet_size: {data['packet_size']}\n"
            f"- duration_ms: {data['duration_ms']}\n"
            f"- protocol: {data['protocol']}"
        )
    }
]

                    
                    response = client.chat.completions.create(
                        model="meta-llama/Llama-3.3-70B-Instruct-Turbo-Free",
                        messages=messages,
                        stream=False,
                    )
                    
                    llm_response = response.choices[0].message.content
                    label, reason = llm_response.split('\n')[:2] if '\n' in llm_response else (llm_response, "No reason provided")
                    
                    print(f"\n🚨 Anomaly Detected!\nLabel: {label}\nReason: {reason}\nConfidence Score: {confidence_score:.4f}\n")
                    
                    csv_writer.writerow([
                        data['src_port'],
                        data['dst_port'],
                        data['packet_size'],
                        data['duration_ms'],
                        data['protocol'],
                        label,
                        reason,
                        confidence_score
                    ])
                else:
                    print("Data is normal.\n")

            except json.JSONDecodeError:
                print("Error decoding JSON.")
            except Exception as e:
                print(f"Error processing data: {e}")

    csv_file.close()