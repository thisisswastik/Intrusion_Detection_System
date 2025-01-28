import streamlit as st
import pandas as pd
import numpy as np
import pyshark
from keras.models import load_model
import joblib

# Load the trained model and scaler
model = load_model("ids_model.keras")
scaler = joblib.load("scaler.pkl")

# Function to preprocess a live packet and extract the features
def preprocess_packet(packet):
    try:
        features = {
            "Bwd Packet Length Std": float(packet.get_multiple_layers_field('tcp.analysis.ack_rtt', 0) or 0),
            "Fwd Seg Size Min": int(packet.tcp.len if hasattr(packet, 'tcp') else 0),
            "Packet Length Variance": float(packet.get_multiple_layers_field('frame.time_delta', 0) or 0),
            "Packet Length Std": float(packet.get_multiple_layers_field('ip.len', 0) or 0),
            "Bwd Packet Length Max": int(packet.get_multiple_layers_field('tcp.len', 0) or 0),
            "Bwd Packet Length Mean": float(packet.get_multiple_layers_field('ip.ttl', 0) or 0),
            "Bwd Segment Size Avg": float(packet.get_multiple_layers_field('tcp.segment_size', 0) or 0),
            "Packet Length Max": int(packet.get_multiple_layers_field('frame.len', 0) or 0),
            "RST Flag Count": int(packet.tcp.flags_rst if hasattr(packet, 'tcp') else 0),
            "Subflow Bwd Bytes": int(packet.get_multiple_layers_field('tcp.payload', 0) or 0),
            "Bwd RST Flags": int(packet.tcp.flags_rst if hasattr(packet, 'tcp') else 0),
            "Packet Length Mean": float(packet.get_multiple_layers_field('ip.len', 0) or 0),
            "Average Packet Size": float(packet.get_multiple_layers_field('ip.len', 0) or 0),
            "SYN Flag Count": int(packet.tcp.flags_syn if hasattr(packet, 'tcp') else 0),
            "Bwd Bulk Rate Avg": 0,  # Placeholder; map this to an available packet field
            "Fwd RST Flags": int(packet.tcp.flags_rst if hasattr(packet, 'tcp') else 0),
            "Dst Port": int(packet.tcp.dstport if hasattr(packet, 'tcp') else 0),
            "Dst IP dec": int(packet.ip.dst if hasattr(packet, 'ip') else 0),
            "FWD Init Win Bytes": int(packet.tcp.window_size if hasattr(packet, 'tcp') else 0),
            "Flow Packets/s": 0,  # Placeholder; calculate this if possible
            "Subflow Fwd Packets": 0,  # Placeholder; map this to an available packet field
            "Bwd Packets/s": 0,  # Placeholder; calculate this if possible
            "Fwd Packets/s": 0,  # Placeholder; calculate this if possible
            "Attempted Category": 0,  # Placeholder
            "Idle Min": 0,  # Placeholder
            "Idle Mean": 0,  # Placeholder
            "Bwd IAT Max": 0,  # Placeholder
            "Fwd IAT Total": 0,  # Placeholder
            "Flow Duration": 0,  # Placeholder
            "Subflow Fwd Bytes": 0,  # Placeholder
            "Fwd Packet Length Mean": float(packet.tcp.len if hasattr(packet, 'tcp') else 0),
            "Fwd Segment Size Avg": float(packet.tcp.len if hasattr(packet, 'tcp') else 0),
            "Bwd IAT Total": 0,  # Placeholder
            "Down/Up Ratio": 0,  # Placeholder
            "Fwd Packet Length Min": float(packet.tcp.len if hasattr(packet, 'tcp') else 0),
            "Bwd Packet Length Min": 0,  # Placeholder
            "Packet Length Min": int(packet.get_multiple_layers_field('frame.len', 0) or 0),
            "Protocol": packet.highest_layer,
            "Src IP dec": int(packet.ip.src if hasattr(packet, 'ip') else 0),
        }

        # Convert the feature dictionary to a DataFrame
        df = pd.DataFrame([features])

        # Handle missing values
        df = df.fillna(0)

        return df

    except Exception as e:
        st.error(f"Error processing packet: {e}")
        return None


# Function to capture live packet
def capture_live_data(interface='eth0'):
    capture = pyshark.LiveCapture(interface=interface)
    for packet in capture.sniff_continuously(packet_count=1):  # Capture 1 packet
        return preprocess_packet(packet)


# Streamlit app
st.title("Intrusion Detection System")
st.write("Real-time intrusion detection using deep learning.")

# Interface input
interface = st.text_input("Enter network interface (e.g., eth0):", value="eth0")

# Ask the user to choose between capturing live data or entering data manually
option = st.radio("Choose input method:", ('Capture Live Packet', 'Enter Data Manually'))

if option == 'Capture Live Packet':
    if st.button("Capture and Predict"):
        # Capture live packet and preprocess
        live_packet = capture_live_data(interface)

        if live_packet is not None:
            # Scale the features
            live_packet_scaled = scaler.transform(live_packet)

            # Make prediction
            prediction = model.predict(live_packet_scaled)
            anomaly_score = prediction[0][0]

            # Display results
            st.write("Prediction:", "Anomaly Detected" if anomaly_score > 0.5 else "Normal Traffic")
            st.write("Anomaly Score:", anomaly_score)

elif option == 'Enter Data Manually':
    # Collect input data from the user for each feature
    user_input = {}
    for feature in ["Bwd Packet Length Std", "Fwd Seg Size Min", "Packet Length Variance", "Packet Length Std", 
                    "Bwd Packet Length Max", "Bwd Packet Length Mean", "Bwd Segment Size Avg", "Packet Length Max", 
                    "RST Flag Count", "Subflow Bwd Bytes", "Bwd RST Flags", "Packet Length Mean", "Average Packet Size", 
                    "SYN Flag Count", "Bwd Bulk Rate Avg", "Fwd RST Flags", "Dst Port", "Dst IP dec", "FWD Init Win Bytes",
                    "Flow Packets/s", "Subflow Fwd Packets", "Bwd Packets/s", "Fwd Packets/s", "Attempted Category", 
                    "Idle Min", "Idle Mean", "Bwd IAT Max", "Fwd IAT Total", "Flow Duration", "Subflow Fwd Bytes", 
                    "Fwd Packet Length Mean", "Fwd Segment Size Avg", "Bwd IAT Total", "Down/Up Ratio", 
                    "Fwd Packet Length Min", "Bwd Packet Length Min", "Packet Length Min", "Protocol", "Src IP dec"]:
        user_input[feature] = st.number_input(f"Enter {feature}:", value=0.0)

    # When the user submits the form, make a prediction
    if st.button("Predict"):
        user_df = pd.DataFrame([user_input])

        # Scale the input
        user_scaled = scaler.transform(user_df)

        # Make prediction
        prediction = model.predict(user_scaled)
        anomaly_score = prediction[0][0]

        # Display results
        st.write("Prediction:", "Anomaly Detected" if anomaly_score > 0.5 else "Normal Traffic")
        st.write("Anomaly Score:", anomaly_score)
