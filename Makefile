path := $(shell find / -name "rdkafkacpp.h" 2> /dev/null)

OBJS = main.o flow_enriched.o consumer.o netflow_builder.o anonymization.o input_parser.o

CPP = first_try.cpp flow-messages-enriched.pb.cc netflow_builder.cpp anonymization.cpp input_parser.cpp
HPP = flow-messages-enriched.pb.h consumer.hpp netflow_builder.hpp structs.hpp anonymization.hpp input_parser.hpp

CC = g++
OPTIONS = -c
INCLUDINGS = -include $(path)
PREFLAGS = -Wall -std=gnu++17 
POSTFLAGS = -lrdkafka++ -lz -lpthread -lrt -pthread -lprotobuf -lcrypto

main: main.o flow_enriched.o consumer.o netflow_builder.o anonymization.o input_parser.o
	$(CC) $(PREFLAGS) -o main $(OBJS) $(POSTFLAGS)

main.o: $(HPP) main.cpp
	$(CC) $(OPTIONS) $(PREFLAGS) $(INCLUDINGS) main.cpp -o main.o $(POSTFLAGS)

flow_enriched.o: $(HPP) flow-messages-enriched.pb.cc
	$(CC) $(OPTIONS) $(PREFLAGS) flow-messages-enriched.pb.cc -o flow_enriched.o $(POSTFLAGS)

consumer.o: consumer.hpp consumer.cpp
	$(CC) $(OPTIONS) $(PREFLAGS) $(INCLUDINGS) consumer.cpp -o consumer.o

netflow_builder.o: structs.hpp netflow_builder.hpp netflow_builder.cpp
	$(CC) $(OPTIONS) $(PREFLAGS) netflow_builder.cpp -o netflow_builder.o

anonymization.o: structs.hpp anonymization.hpp anonymization.cpp
	$(CC) $(OPTIONS) $(PREFLAGS) anonymization.cpp -o anonymization.o

input_parser.o: structs.hpp input_parser.hpp input_parser.cpp
	$(CC) $(OPTIONS) $(PREFLAGS) input_parser.cpp -o input_parser.o

clean:
	rm -f *.o main
