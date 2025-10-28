#ifndef FASTDDS_SECURITY_CRYPTOGRAPHY_AESGCMGMACFAST_EXTHANDLES_H
#define FASTDDS_SECURITY_CRYPTOGRAPHY_AESGCMGMACFAST_EXTHANDLES_H

#include <fastdds/rtps/security/cryptography/CryptoKeyFactory.h>
#include <fastdds/rtps/attributes/PropertyPolicy.h>

#include <security/cryptography/AESGCMGMACFAST_Types.h>
#include <security/cryptography/AESGCMGMAC_Types.h>

#include <memory>
#include <atomic>
#include <chrono>
#include <thread>
#include <cstring>
#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <openssl/evp.h>

namespace eprosima {
namespace fastrtps {
namespace rtps {
namespace security {

constexpr size_t BUFFER_SIZE = KEYSTREAM_SIZE * MAX_ROUND_SIZE;

struct CircularBuffer{
    unsigned char keystreams[BUFFER_SIZE][AES_GCM_BLOCK_SIZE];
    std::atomic<int> head;
    std::atomic<int> tail;
    std::atomic<bool> stop_round;
    std::atomic<int> session;
    std::atomic<int> last;
    std::ofstream log;
    std::ofstream log_key;

    CircularBuffer(uint32_t session_id, bool type) : head(0), tail(0), stop_round(false), last(MAX_ROUND_SIZE) {
        session.store(session_id, std::memory_order_release);

        auto now = std::chrono::system_clock::now();
        auto millis = std::chrono::duration_cast<std::chrono::milliseconds>(
                now.time_since_epoch()).count();

        /*
        std::string t = (type) ? "encrypt" : "decrypt";
        std::string filename = "/home/user/" + t + "_ring_buffer_" + std::to_string(session_id) + "_" + std::to_string(millis) + ".log";
        log.open(filename, std::ios::app);

  //      std::string filename_key = "/home/user/" + t + "_keystream_" + std::to_string(session_id) + "_" + std::to_string(millis) + ".log";
  //      log_key.open(filename_key, std::ios::app);
  */
        
    }

    size_t remain_size() const
    {
        int h = head.load();
        int t = tail.load();

        if(h > t)
            return h - t;
        else
            return BUFFER_SIZE - t + h - 1;
    }

    size_t get_last()
    {
        return last.load();
    }

    void set_last(int l)
    {
        last.store(l);
    }

    bool push(EVP_CIPHER_CTX* ctx)
    {

//        auto start = std::chrono::steady_clock::now();
        int block_cnt;
        uint32_t session_id = session.load(std::memory_order_acquire);
  //     fprintf(stdout, "session start\n", session_id);

        //max_blocks_per_session
        for(int round = 0; round < MAX_ROUND_SIZE; round++){

            //log <<"==" << session_id << "  ROUND " << round << " start ==" << std::endl;
            //fprintf(stdout, "[%u] ROUND %d start\n", session_id, round);


            //max iv counter
            for(size_t i = 0; i < KEYSTREAM_SIZE; i += CHUNK_SIZE){
/*
                auto end = std::chrono::steady_clock::now();
                auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
                if(elapsed > std::chrono::milliseconds(50)){
                std::cout << "[LOG] 50ms 경과: 함수 실행 후 " 
                                  << std::chrono::duration_cast<std::chrono::milliseconds>(
                                                               std::chrono::steady_clock::now() - start
                                                                                ).count()
                                                << "ms 지남\n";
                return true;
                }
                */
                if(stop_round.load(std::memory_order_acquire)){
                    //log <<"[" << round << " ROUND ] aborted due to overrun" << std::endl; 

                    int h = head.load(std::memory_order_acquire);
                    int t = tail.load(std::memory_order_acquire);
                    round += (h - t) / KEYSTREAM_SIZE;
                    add_gctx_ctr(ctx, h - t);
                    
                    tail.store(h, std::memory_order_release);
                    t = tail.load(std::memory_order_acquire);
                    //log <<"Tail adjusted to head (" << h << " to " << t << ")" << std::endl;
                    stop_round.store(false, std::memory_order_release);
                    break;
                }
                //borim
                // size_t cur_chunk = std::min(static_cast<size_t>(CHUNK_SIZE), KEYSTREAM_SIZE - i);
                size_t cur_chunk = CHUNK_SIZE;

                int h = head.load(std::memory_order_acquire);
                int t = tail.load(std::memory_order_acquire);
                //log <<"[" << round << "] remain buffer size = " << remain_size() << " | head : " << h << " | tail : " << t << std::endl;

                while(remain_size() <= cur_chunk){
                    //log <<"[" << session_id << "] wait for make keystream | i = " << i << std::endl;
                    std::this_thread::sleep_for(std::chrono::nanoseconds(WAIT_INTERVAL));
                }

                int cur_tail = t;
                size_t space_end = BUFFER_SIZE - cur_tail;

                if(space_end >= cur_chunk){
                    jinho_EVP_EncryptUpdate(ctx, keystreams[t], &block_cnt, (const unsigned char *)"A", cur_chunk);
                } else{
                    //log <<"space end : " << space_end << " | cur_chunk : " << cur_chunk << std::endl;
                    jinho_EVP_EncryptUpdate(ctx, keystreams[t], &block_cnt, (const unsigned char *)"A", space_end);
                    jinho_EVP_EncryptUpdate(ctx, keystreams[0], &block_cnt, (const unsigned char *)"A", cur_chunk - space_end);
                }

                tail.store((t + cur_chunk) % BUFFER_SIZE);
/*
                for(size_t k = 0; k < cur_chunk_; k++){
                    log_key << "Tail : " << t + k << "| Data :";
                    for (size_t j = 0; j < 16; j++)
                        log_key << std::hex << std::setw(2) << std::setfill('0') << (int)keystreams[t + k][j] << " ";
                    log_key << std::dec << std::endl;
                }
  */              
            }
        }

        return true;
    }

    void move_head(int shift){
        int h = head.load(std::memory_order_acquire);
        int t = tail.load(std::memory_order_acquire);
        int new_head = (h + shift) % BUFFER_SIZE;

        //log <<"==== h : " << h << " | new_head : " << new_head << " | tail : " << t << std::endl;   
        //log <<"--- remain_size : " << BUFFER_SIZE - remain_size() << " | shift " << shift << " --- " << std::endl;

        while(stop_round.load()){
            std::this_thread::sleep_for(std::chrono::nanoseconds(WAIT_INTERVAL));
            //log <<"*** move head wait moving tail head : " << h << " | tail : " << tail << " ***" << std::endl;
        }

        if(BUFFER_SIZE - remain_size() < shift){
            //log <<"[Trigger] Overrun detected! Stop current round" << std::endl;
            head.store(new_head, std::memory_order_release);
            stop_round.store(true, std::memory_order_release);
        }
        
        while(stop_round.load()){
            //log <<"*** move head wait moving tail head : " << h << " / tail : " << tail << " ***" << std::endl;
            std::this_thread::sleep_for(std::chrono::nanoseconds(WAIT_INTERVAL));
        }


        //log <<"Keystream sync adjusted: head=" << new_head
                  //<< " (shift=" << shift << ")" << std::endl;
                  
    }

    unsigned char * get_keystream(int len, int block_cnt, EVP_CIPHER_CTX * ctx)
    {
        uint32_t session_id = session.load(std::memory_order_acquire);
        //log <<"--- get_keystream : " << session_id << " | size : " << len << " | bcnt = " << block_cnt << "  ---" << std::endl;
        //fprintf(stdout, "[%u] get keystream size : %d | bnt = %d\n", session_id, len, block_cnt);

        int blocks_needed = (len + AES_GCM_BLOCK_SIZE - 1) / AES_GCM_BLOCK_SIZE;
        unsigned char *buf = (unsigned char (*))malloc(blocks_needed * AES_GCM_BLOCK_SIZE);
        if(!buf)
            return NULL;

        unsigned char* out_ptr = buf;
        int res = blocks_needed;
        int h, t;
        int l = last.load(std::memory_order_acquire);
        int diff = (l != MAX_ROUND_SIZE) ? block_cnt - l : block_cnt - 0;

        if(diff){
            //log <<"sync " << l << " to " << block_cnt << " | move block " << diff << std::endl;
            int shift = diff * KEYSTREAM_SIZE;

            move_head(shift);
        }
        
        while(stop_round.load()){}

            while(res > 0){
                h = head.load(std::memory_order_acquire);
                t = tail.load(std::memory_order_acquire);

                int item_len = (h <= t) ? (t - h) : (BUFFER_SIZE - h + t);
                if(item_len <= 0) continue;

 //               //log <<"item_len : " << item_len << std::endl;

                int cnt = (item_len < res) ? item_len : res;

                int first_part = std::min<int>(cnt, BUFFER_SIZE - h);
                memcpy(out_ptr, keystreams[h], AES_GCM_BLOCK_SIZE * first_part);

                if(cnt > first_part){
                    memcpy(out_ptr + (first_part * AES_GCM_BLOCK_SIZE),
                            keystreams[0],
                            AES_GCM_BLOCK_SIZE * (cnt - first_part));
                }

//                //log <<"[get] move head to " << (h + cnt) % BUFFER_SIZE << std::endl;
                head.store((h + cnt) % BUFFER_SIZE, std::memory_order_release);
                res -= cnt;
                out_ptr += (cnt * AES_GCM_BLOCK_SIZE);
            }

//        //log <<"out while" << std::endl;
        //borim
        // move_head((KEYSTREAM_SIZE - blocks_needed));
        
        last.store(block_cnt + 1, std::memory_order_release);

       //log <<"head : " << head.load(std::memory_order_acquire) << std::endl;
        //log <<"tail : " << tail.load(std::memory_order_acquire) << std::endl;
        //log <<"block count : " << block_cnt << " | get keystream : ";
/*
        for(int i = 0; i < blocks_needed * AES_GCM_BLOCK_SIZE; i++){
            //log <<std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(buf[i]) << " ";
        }
        //log <<std::dec << std::endl;
*/

        return buf;
    }
};

struct AESGCMGMACFAST_WriterCryptoHandleImpl
    : public HandleImpl<EntityKeyHandle, AESGCMGMACFAST_KeyFactory>
{
    using HandleImpl<EntityKeyHandle, AESGCMGMACFAST_KeyFactory>::nil;
    using BaseType = HandleImpl<EntityKeyHandle, AESGCMGMACFAST_KeyFactory>;

    std::shared_ptr<CircularBuffer> e_buffer;
    EVP_CIPHER_CTX* e_ctx = nullptr;
    uint32_t e_session = 0;
    std::array<uint8_t, 32> e_key{};

    std::shared_ptr<CircularBuffer> d_buffer;
    EVP_CIPHER_CTX* d_ctx = nullptr;
    uint32_t d_session = 0;
    std::array<uint8_t, 32> d_key{};

    static AESGCMGMACFAST_WriterCryptoHandleImpl& narrow(DatawriterCryptoHandle& handle)
    {
        return static_cast<AESGCMGMACFAST_WriterCryptoHandleImpl&>(
                BaseType::narrow(handle));
                
    }

    static BaseType& narrow_base(DatawriterCryptoHandle& handle)
    {
        return static_cast<BaseType&>(
                BaseType::narrow(handle));
    }
};
    
struct AESGCMGMACFAST_ReaderCryptoHandleImpl
    : public HandleImpl<EntityKeyHandle, AESGCMGMACFAST_KeyFactory>
{
    using HandleImpl<EntityKeyHandle, AESGCMGMACFAST_KeyFactory>::nil;
    using BaseType = HandleImpl<EntityKeyHandle, AESGCMGMACFAST_KeyFactory>;

    static AESGCMGMACFAST_ReaderCryptoHandleImpl& narrow(DatawriterCryptoHandle& handle)
    {
        return static_cast<AESGCMGMACFAST_ReaderCryptoHandleImpl&>(
                HandleImpl<EntityKeyHandle, AESGCMGMACFAST_KeyFactory>::narrow(handle));
    }

    static BaseType& narrow_base(DatawriterCryptoHandle& handle)
    {
        return static_cast<BaseType&>(
                BaseType::narrow(handle));
    }
};

struct AESGCMGMACFAST_EntityCryptoHandleImpl
    : public HandleImpl<EntityKeyHandle, AESGCMGMACFAST_KeyFactory>
{
    using HandleImpl<EntityKeyHandle, AESGCMGMACFAST_KeyFactory>::nil;

    static AESGCMGMACFAST_EntityCryptoHandleImpl& narrow(DatawriterCryptoHandle& handle)
    {
        return static_cast<AESGCMGMACFAST_EntityCryptoHandleImpl&>(
                HandleImpl<EntityKeyHandle, AESGCMGMACFAST_KeyFactory>::narrow(handle));
    }
};
typedef AESGCMGMACFAST_WriterCryptoHandleImpl AESGCMGMACFAST_WriterCryptoHandle;
typedef AESGCMGMACFAST_ReaderCryptoHandleImpl AESGCMGMACFAST_ReaderCryptoHandle;
typedef AESGCMGMACFAST_EntityCryptoHandleImpl AESGCMGMACFAST_EntityCryptoHandle;
/*
using AESGCMGMACFAST_WriterCryptoHandle = std::shared_ptr<AESGCMGMACFAST_WriterCryptoHandleImpl>;
using AESGCMGMACFAST_ReaderCryptoHandle = std::shared_ptr<AESGCMGMACFAST_ReaderCryptoHandleImpl>;
using AESGCMGMACFAST_EntityCryptoHandle = std::shared_ptr<AESGCMGMACFAST_EntityCryptoHandleImpl>;
*/
}
}
}
}

#endif
