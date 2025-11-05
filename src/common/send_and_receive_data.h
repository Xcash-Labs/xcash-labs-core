#pragma once

#include <string>
#include "cryptonote_config.h"

namespace xcash_net {
    std::string send_and_receive_data(std::string IP_address,std::string data2, 
        int send_or_receive_socket_data_timeout_settings = SEND_OR_RECEIVE_SOCKET_DATA_TIMEOUT_SETTINGS);
}