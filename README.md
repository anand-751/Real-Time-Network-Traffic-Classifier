# Real-Time-Network-Traffic-Classifier

.

📦 **Features**


📡 Captures live TCP and UDP packets using libpcap

🧠 Applies heuristic rules to classify traffic using port numbers

🗃️ Logs classification output clearly in real time

⚡ Lightweight, fast, and runs directly in terminal

🛠️ **Technologies**

Language: C++

Libraries:

libpcap (packet capture)

Standard POSIX headers like <netinet/in.h>, <arpa/inet.h>, <pcap.h>, etc.

Build System: Makefile

OS: Linux (Ubuntu/Debian tested)

Privileges: Requires sudo to access network interfaces

----------------------------------------------------------------------


🚀 **Getting Started**

Install necessary tools:


sudo apt update

sudo apt install g++ libpcap-dev


🛠️ **Build the Project**

Clone the repository and compile the source:

git clone https://github.com/your-username/real-time-network-classifier.git

cd real-time-network-classifier

make

▶️ **Run the Program**

sudo ./build/sniffer
