#include <iostream>

#include "consumer.hpp"

Consumer::Consumer()
{
    std::cout << ">> Empty consumer has been created." << std::endl;
}

Consumer::Consumer(std::string _username, std::string _password, std::string _group_id, 
    std::string _security_protocol, std::string _sasl_mechanism, std::string _ssl_ca_location, std::string _brokers) 
    : errstr{}, global_conf{RdKafka::Conf::create(RdKafka::Conf::CONF_GLOBAL)},
    topic_conf{RdKafka::Conf::create(RdKafka::Conf::CONF_TOPIC)},
    consumer{}, reb_cb_obj{}, 
    username{_username}, password{_password}, group_id{_group_id}, security_protocol{_security_protocol},
    sasl_mechanism{_sasl_mechanism}, ssl_ca_location{_ssl_ca_location}, 
    brokers{_brokers}, topics{}
    {
        reb_cb_obj = std::make_shared<CRebalanceCb>();
        std::cout << ">> Consumer " << username << " has been created." << std::endl;
    }

Consumer::~Consumer()
{
    std::cout << "<< Consumer " << username << " has ben destroyed. " << std::endl;
}

int 
Consumer::init_consumer_default()
{
    if(global_conf->set("rebalance_cb", reb_cb_obj.get(), errstr) != RdKafka::Conf::CONF_OK) {
        std::cerr << errstr << std::endl;
        return -1;
    }

    if(global_conf->set("sasl.username", username, errstr) != RdKafka::Conf::CONF_OK) {
        std::cerr << errstr << std::endl;
        return -1;
    }

    if(global_conf->set("sasl.password", password, errstr) != RdKafka::Conf::CONF_OK) {
        std::cerr << errstr << std::endl;
        return -1;
    }

    if(global_conf->set("group.id", group_id, errstr) != RdKafka::Conf::CONF_OK) {
        std::cerr << errstr << std::endl;
        return -1;
    }

    if(global_conf->set("security.protocol", security_protocol, errstr) != RdKafka::Conf::CONF_OK) {
        std::cerr << errstr << std::endl;
        return -1;
    }

    if(global_conf->set("sasl.mechanisms", sasl_mechanism, errstr) != RdKafka::Conf::CONF_OK) {
        std::cerr << errstr << std::endl;
        return -1;
    }

    if(global_conf->set("ssl.ca.location", ssl_ca_location, errstr) != RdKafka::Conf::CONF_OK) {
        std::cerr << errstr << std::endl;
        return -1;
    }

    if(global_conf->set("bootstrap.servers", brokers, errstr) != RdKafka::Conf::CONF_OK) {
        std::cerr << errstr << std::endl;
        return -1;
    }

    if(global_conf->set("auto.offset.reset", "smallest", errstr) != RdKafka::Conf::CONF_OK) {
        std::cerr << errstr << std::endl;
        return -1;
    }

    if(global_conf->set("default_topic_conf", topic_conf.get(), errstr) != RdKafka::Conf::CONF_OK) {
        std::cerr << errstr << std::endl;
        return -1;
    }

    consumer = std::shared_ptr<RdKafka::KafkaConsumer>{RdKafka::KafkaConsumer::create(global_conf.get(), errstr)};

    if(!consumer) {
        std::cerr << "Failed to initialize consumer itself: " << errstr << std::endl;
        return -1;
    }

    std::cout << ">> Consumer " << username << " has been successfully initialized." << std::endl;
    return 0;
}

int 
Consumer::add_topics(const std::vector<std::string>& input)
{
    topics.insert(topics.end(), input.begin(), input.end());
    return 0;
}

int
Consumer::subscribe()
{
    /* EXPERIMENTAL */
    /*
    int64_t low, high;
    RdKafka::HandleImpl exp{};
    exp.get_watermark_offsets("flow-messages-enriched", 0, &low, &high);
    std::cout << "LOW: " << low << "; HIGH: " << high << std::endl;

    std::vector<RdKafka::TopicPartition*> partitions;
    partitions.push_back(RdKafka::TopicPartition::create("flow-messages-enriched", 0, RdKafka::Topic::OFFSET_END));
    partitions.push_back(RdKafka::TopicPartition::create("flow-messages-enriched", 1, RdKafka::Topic::OFFSET_END));
    partitions.push_back(RdKafka::TopicPartition::create("flow-messages-enriched", 2, RdKafka::Topic::OFFSET_END));
    */
    /* END EXPERIMENTAL */
    
    
    RdKafka::ErrorCode err = consumer->subscribe(topics);
    if(err) {
        std::cerr << "Failed to subscribe to " << topics.size() << " topics: "
            << RdKafka::err2str(err) << std::endl;
        return -1;
    }
    
    /*
    consumer->unassign();

    consumer->assign(partitions);
    consumer->commitAsync();
    */
    return 0;
}

std::shared_ptr<RdKafka::Message> 
Consumer::consume(int timeout_ms) const
{
   std::shared_ptr<RdKafka::Message> msg{consumer->consume(timeout_ms)};
   return msg;
}

int
Consumer::close()
{
    consumer->close();
    return 0;
}

void 
Consumer::CRebalanceCb::rebalance_cb (RdKafka::KafkaConsumer *consumer, RdKafka::ErrorCode err,
    std::vector<RdKafka::TopicPartition*> &partitions)
{
    if (err == RdKafka::ERR__ASSIGN_PARTITIONS) {
        for(auto const& value: partitions) {
            value->set_offset(RdKafka::Topic::OFFSET_END);
        }
        consumer->assign(partitions);
    } else {
        consumer->unassign();
    }
}
