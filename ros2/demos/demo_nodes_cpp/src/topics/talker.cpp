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

#include <chrono>
#include <cstdio>
#include <memory>
#include <utility>
#include <ctime>
#include <iostream>

#include "rclcpp/rclcpp.hpp"
#include "rclcpp_components/register_node_macro.hpp"

#include "std_msgs/msg/string.hpp"

#include "demo_nodes_cpp/visibility_control.h"

using namespace std::chrono_literals;

namespace demo_nodes_cpp
{
// Create a Talker class that subclasses the generic rclcpp::Node base class.
// The main function below will instantiate the class as a ROS node.
class Talker : public rclcpp::Node
{
public:
  DEMO_NODES_CPP_PUBLIC
  explicit Talker(const rclcpp::NodeOptions & options)
  : Node("talker", options)
  {
    // Create a function for when messages are to be sent.
    setvbuf(stdout, NULL, _IONBF, BUFSIZ);

    auto publish_message =
      [this]() -> void
      {
            std::string data(target_length, 'A');
            msg_ = std::make_unique<std_msgs::msg::String>();
            auto n_ = std::chrono::system_clock::now();
            auto ms = std::chrono::duration_cast<std::chrono::nanoseconds>(n_.time_since_epoch()) % 1000000000;
            std::time_t t = std::chrono::system_clock::to_time_t(n_);
           
            std::tm local_tm{};
            localtime_r(&t, &local_tm);

            std::ostringstream oss;
            oss << std::put_time(&local_tm, "%H%M%S") << '.' << std::setfill('0') << std::setw(9) << ms.count();

            std::string timestamp = oss.str();
            data.insert(0, timestamp);
       
            msg_->data = data;
            RCLCPP_INFO(this->get_logger(), "Publishing: '%s'", msg_->data.c_str());
            pub_->publish(std::move(msg_));
      };
    rclcpp::QoS qos(rclcpp::KeepLast{7});
    pub_ = this->create_publisher<std_msgs::msg::String>("chatter", qos);

    // Use a timer to schedule periodic message publishing.
    timer_ = this->create_wall_timer(50ms, publish_message);
  }

private:
  std::unique_ptr<std_msgs::msg::String> msg_;
  rclcpp::Publisher<std_msgs::msg::String>::SharedPtr pub_;
  rclcpp::TimerBase::SharedPtr timer_;
  const size_t target_length = 64588;
};

}  // namespace demo_nodes_cpp

RCLCPP_COMPONENTS_REGISTER_NODE(demo_nodes_cpp::Talker)
