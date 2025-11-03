# 🔒 Precomputation_FastDDS

**Precomputation_FastDDS** integrates a pre-computation–enabled OpenSSL ([link](https://github.com/skqhfla/FastOpenSSL)) into **Fast-DDS**,  
allowing AES-GCM encryption/decryption with pre-generated keystreams for enhanced communication performance.

---

## ⚙️ Build Instructions

1️⃣ **Add** the pre-computation–enabled OpenSSL files to your existing **Fast-DDS** source.  
2️⃣ **Rebuild** Fast-DDS and ROS 2:

```bash
# Build for Fast-DDS and ROS 2
colcon build --cmake-args -DSECURITY=on -DOPENSSL_ROOT_DIR=<FastOpenSSL_build_path>
```

---

## 🚀 Run the Sample Code

Set the **ROS_DOMAIN_ID** according to the desired encryption mode:

| ROS_DOMAIN_ID | Description |
|----------------|-------------|
| `0` | Uses Pre-computation enabled OpenSSL |
| Others | Uses default OpenSSL |

**Example:**
```bash
export ROS_DOMAIN_ID=0
ros2 run <your_package> <your_node>
```

