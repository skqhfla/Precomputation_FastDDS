// Copyright 2014 Open Source Robotics Foundation, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "rclcpp/rclcpp.hpp"
#include "rclcpp_components/register_node_macro.hpp"

#include "std_msgs/msg/string.hpp"

#include "demo_nodes_cpp/visibility_control.h"
#include <iostream>

namespace demo_nodes_cpp
{
    // Create a Listener class that subclasses the generic rclcpp::Node base class.
    // The main function below will instantiate the class as a ROS node.
    class Listener : public rclcpp::Node
    {
        public:
            DEMO_NODES_CPP_PUBLIC
                explicit Listener(const rclcpp::NodeOptions & options)
                : Node("listener", options)
                {
                    // Create a callback function for when messages are received.
                    // Variations of this function also exist using, for example UniquePtr for zero-copy transport.
                    setvbuf(stdout, NULL, _IONBF, BUFSIZ);
                    auto callback =
                        [this](std_msgs::msg::String::ConstSharedPtr msg) -> void
                        {
                            count_++;
                            std::string prefix = msg->data.substr(0, 16);  // 2025-10-23 15:24:51.083 등
                            auto now = std::chrono::system_clock::now();
                            auto ms = std::chrono::duration_cast<std::chrono::nanoseconds>(
                                    now.time_since_epoch()) % 1000000000;
                            std::time_t t = std::chrono::system_clock::to_time_t(now);

                            std::tm local_tm{};
                            localtime_r(&t, &local_tm);

                            std::ostringstream oss;
                            oss << std::put_time(&local_tm, "%H%M%S")
                                << '.' << std::setfill('0') << std::setw(9) << ms.count();
                            std::string recv_time = oss.str();
                            fprintf(stdout,
                                    "[Recv] msg_prefix: %s | recv_time: %s\n",
                                    prefix.c_str(), recv_time.c_str());
                            RCLCPP_INFO(this->get_logger(), "I heard: [%s]", msg->data.c_str());
                        };
                    // Create a subscription to the topic which can be matched with one or more compatible ROS
                    // publishers.
                    // Note that not all publishers on the same topic with the same type will be compatible:
                    // they must have compatible Quality of Service policies.
                    sub_ = create_subscription<std_msgs::msg::String>("chatter", 10, callback);
                }

        private:
            rclcpp::Subscription<std_msgs::msg::String>::SharedPtr sub_;

            size_t count_ = 0;
            std::chrono::steady_clock::time_point start_time_;
    };

}  // namespace demo_nodes_cpp

RCLCPP_COMPONENTS_REGISTER_NODE(demo_nodes_cpp::Listener)
