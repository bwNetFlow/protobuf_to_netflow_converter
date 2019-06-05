#ifndef CONSUMER_HPP
#define CONSUMER_HPP

#include <memory>
#include <vector>

/* --- TODO: Check if constructor parameters are reasonable --- */

class Consumer
{
    public:
        Consumer();

        Consumer(std::string _username, std::string _password, std::string _group_id,
            std::string _security_protocol, std::string _sasl_mechanism, 
            std::string _ssl_ca_location, std::string _brokers);

        ~Consumer();
        
        int init_consumer_default();

        int add_topics(const std::vector<std::string>& input);

        int subscribe();

        std::shared_ptr<RdKafka::Message> consume(int timeout_ms) const;

        int close();
    private:
        std::string errstr;

        std::shared_ptr<RdKafka::Conf> global_conf;
        std::shared_ptr<RdKafka::Conf> topic_conf;
        std::shared_ptr<RdKafka::KafkaConsumer> consumer;

        std::string username;
        std::string password;
        std::string group_id;
        std::string security_protocol;
        std::string sasl_mechanism;
        std::string ssl_ca_location;
        std::string brokers;
        std::vector<std::string> topics;
};

#endif
