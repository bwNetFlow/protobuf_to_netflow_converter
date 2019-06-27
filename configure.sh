#!/bin/sh

# Creating Directory
mkdir ~/tmpWorDir
cd ~/tmpWorDir

# Installing Kafka (librdkafka) for C/C++
#wget -qO - https://packages.confluent.io/deb/5.2/archive.key | sudo apt-key add -
#sudo add-apt-repository "deb [arch=amd64] https://packages.confluent.io/deb/5.2 stable main"
#sudo apt-get update && sudo apt-get install -y librdkafka-dev
git clone https://github.com/edenhill/librdkafka.git
cd librdkafka
./configure --install-deps
make
sudo make install
cd ..

# Installing Required SSL Package
#sudo apt install -y libssl-dev zlib1g-dev pkg-config

# Installing Google Protobuf for C/C++
sudo apt-get -y install autoconf automake libtool curl make g++ unzip
wget https://github.com/protocolbuffers/protobuf/releases/download/v3.7.1/protobuf-cpp-3.7.1.zip -P ~/tmpWorDir
unzip protobuf-cpp-3.7.1.zip -d ~/tmpWorDir
cd protobuf-3.7.1
./configure
make
make check
sudo make install
sudo ldconfig
cd ..

# Deleting Before Created Directory
sudo rm -rf ~/tmpWorDir
