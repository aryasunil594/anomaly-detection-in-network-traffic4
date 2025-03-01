import streamlit as st 
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

# Page configuration
st.set_page_config(
    page_title="ANOMALY DETECTION IN NETWORK TRAFFIC",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# Custom CSS for better styling
st.markdown("""
    <style>
    .main-header {
        font-size: 2.5rem;
        font-weight: 700;
        color: #FFFFFF;
        padding: 1rem 0;
        text-align: center;
        background: linear-gradient(90deg, #1E3A8A, #2563EB);
        border-radius: 10px;
        margin-bottom: 2rem;
    }
    .section-header {
        font-size: 1.5rem;
        color: #3B82F6;
        padding: 0.5rem 0;
        border-bottom: 2px solid #3B82F6;
        margin-bottom: 1rem;
    }
    .metric-container {
        background-color: #1E293B;
        padding: 1.5rem;
        border-radius: 10px;
        margin-bottom: 1rem;
    }
    .anomaly-score {
        font-size: 1.8rem;
        font-weight: bold;
        margin: 1rem 0;
    }
    </style>
""", unsafe_allow_html=True)

# Load dataset
@st.cache_data
def load_data():
    data = pd.read_csv('synthetic_network_traffic.csv')
    return data

# Load and prepare data
data = load_data()
features = ['BytesSent', 'BytesReceived', 'PacketsSent', 'Duration']
X = data[features]

# Calculate statistical bounds for normal traffic
bounds = {
    'BytesSent': {'mean': X['BytesSent'].mean(), 'std': X['BytesSent'].std()},
    'BytesReceived': {'mean': X['BytesReceived'].mean(), 'std': X['BytesReceived'].std()},
    'PacketsSent': {'mean': X['PacketsSent'].mean(), 'std': X['PacketsSent'].std()},
    'Duration': {'mean': X['Duration'].mean(), 'std': X['Duration'].std()}
}

# Data scaling
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# Train Isolation Forest model with adjusted parameters
model = IsolationForest(
    contamination=0.2,  # Adjusted contamination
    random_state=42,
    n_estimators=150,
    max_samples='auto'
)
model.fit(X_scaled)

# Main header
st.markdown('<div class="main-header">🔍 ANOMALY DETECTION IN NETWORK TRAFFIC</div>', unsafe_allow_html=True)

# Create input columns
col1, col2 = st.columns(2)
with col1:
    st.subheader("Traffic Source")
    src_bytes = st.number_input("Source Bytes", min_value=0, value=1000)
    dst_bytes = st.number_input("Destination Bytes", min_value=0, value=1200)
    src_port = st.number_input("Source Port", min_value=0, value=80)
    dst_port = st.number_input("Destination Port", min_value=0, value=443)

with col2:
    st.subheader("Traffic Metrics")
    packets_sent = st.number_input("Packets Sent", min_value=1, value=100)
    packets_received = st.number_input("Packets Received", min_value=1, value=100)
    duration = st.number_input("Duration (seconds)", min_value=1, value=10)
    protocol = st.selectbox("Protocol", ["TCP", "UDP", "ICMP"])

# Map protocol to numerical values
protocol_map = {"TCP": 1, "UDP": 2, "ICMP": 3}
protocol_num = protocol_map[protocol]

# Center the detect button
col1, col2, col3 = st.columns([1, 2, 1])
with col2:
    detect_button = st.button('Detect Anomaly', use_container_width=True)

if detect_button:
    # Prepare input data
    input_data = np.array([[src_bytes, dst_bytes, packets_sent, duration]])
    input_data_scaled = scaler.transform(input_data)
    
    # Get anomaly score
    anomaly_score = model.score_samples(input_data_scaled)[0]
    
    # Calculate metrics
    bytes_per_packet = (src_bytes + dst_bytes) / packets_sent
    bytes_per_second = (src_bytes + dst_bytes) / duration
    packets_per_second = packets_sent / duration
    
    # Define normal conditions
    normal_conditions = [
        bytes_per_packet <= 500,  # Maximum TCP packet size
        bytes_per_second <= 500000,  # 1 MB/s
        packets_per_second <= 5000,  # Max packets per second
        anomaly_score >= -1 # Adjusted threshold for anomaly score
    ]
    
    # Determine if traffic is normal or anomalous
    if all(normal_conditions):
        is_anomaly = False  # All conditions are met, traffic is normal
    else:
        is_anomaly = True  # One or more conditions are violated, anomaly detected
    
    # Display results in a container
    st.markdown('<div class="section-header">Analysis Results</div>', unsafe_allow_html=True)
    
    with st.container():
        if is_anomaly:
            st.error("⚠ Anomaly Detected")
            st.markdown(f"Anomaly Score: {anomaly_score:.3f}", unsafe_allow_html=True)
        else:
            st.success("✅ Normal Traffic Pattern")
            st.markdown(f"Anomaly Score: {anomaly_score:.3f}", unsafe_allow_html=True)
        
        # Display metrics in two columns
        metric_col1, metric_col2 = st.columns(2)
        
        with metric_col1:
            st.markdown('<div class="metric-container">', unsafe_allow_html=True)
            st.write("📊 Traffic Volume")
            st.write(f"Total Bytes: {src_bytes + dst_bytes:,}")
            st.write(f"Packets: {packets_sent:,}")
            st.write(f"Duration: {duration}s")
            st.markdown('</div>', unsafe_allow_html=True)
        
        with metric_col2:
            st.markdown('<div class="metric-container">', unsafe_allow_html=True)
            st.write("📈 Performance Metrics")
            st.write(f"Bytes/Packet: {bytes_per_packet:.2f}")
            st.write(f"Bytes/Second: {bytes_per_second:.2f}")
            st.write(f"Packets/Second: {packets_per_second:.2f}")
            st.markdown('</div>', unsafe_allow_html=True)

            
# Display example patterns
st.write("\nSuggested test patterns:")
st.write("Normal traffic example:")
st.write("- Source Bytes: 1000")
st.write("- Destination Bytes: 1200")
st.write("- Packets Sent: 100")
st.write("- Packets Received: 100")
st.write("- Duration: 10")
st.write("- Source Port: 80")
st.write("- Destination Port: 443")
st.write("- Protocol: TCP")

st.write("\nAnomalous traffic example:")
st.write("- Source Bytes: 1000000")
st.write("- Destination Bytes: 1000000")
st.write("- Packets Sent: 10")
st.write("- Packets Received: 5")
st.write("- Duration: 1")
st.write("- Source Port: 5000")
st.write("- Destination Port: 22")
st.write("- Protocol: UDP")

