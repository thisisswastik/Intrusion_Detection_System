# Intrusion_Detection_System
It contains a trained ANN model fine-tuned with keras-tuner which is used for detecting intrusion on your server. The given model can be modified and deployed on the server as the user wants. The dataset used was CICIDS-17 
# Intrusion Detection System (IDS) with Deep Learning

## Overview
This project implements an Intrusion Detection System (IDS) using deep learning for real-time packet analysis. The system predicts whether the network traffic is normal or contains an anomaly based on various features extracted from live network packets.

The model uses features such as packet lengths, flow duration, flags, and more to make predictions. The deployment leverages Streamlit for easy user interaction, allowing users to either capture live network traffic or enter data manually.

## Features
- **Real-time Packet Capture**: Captures live network traffic using PyShark and analyzes packets in real-time.
- **Manual Data Input**: Allows users to input network traffic features manually for prediction.
- **Deep Learning Model**: Uses a pre-trained Keras model for anomaly detection.
- **Scalability**: Scalable for large networks, as it processes packets and scales features for predictions.

## Requirements
To run this project, make sure you have the following dependencies installed:

- Python 3.6+
- Streamlit
- Keras
- TensorFlow
- Scikit-learn
- PyShark
- Pandas
- Joblib

You can install the necessary dependencies using pip:

```bash
pip install streamlit keras tensorflow scikit-learn pyshark pandas joblib
